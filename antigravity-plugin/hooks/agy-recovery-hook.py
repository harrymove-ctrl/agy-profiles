#!/usr/bin/env python3
"""Antigravity lifecycle hook for automatic model-error retry, quota failover, and post-login recovery."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

CAPACITY_OR_TRANSIENT_RE = re.compile(
    r"(?:no\s+capacity\s+available|unavailable\s*\(code\s*503\)|\b503\b.*capacity|overloaded|"
    r"http2:\s*server\s+sent\s+goaway|stream\s+reading\s+error|stream\s+idle\s+timeout|"
    r"context\s+deadline\s+exceeded|agent\s+execution\s+terminated\s+due\s+to\s+error)",
    re.IGNORECASE,
)
QUOTA_OR_AUTH_RE = re.compile(
    r"(?:resource_exhausted|quota\s+reached|quota\s+exhausted|insufficient_g1_credits_balance|"
    r"unknown\s+model\s+key|failed\s+to\s+construct\s+executor|not\s+logged\s+into\s+antigravity|\b429\b)",
    re.IGNORECASE,
)
HOOK_LEDGER_FILENAME = ".hook-retry-ledger.json"
STALLED_QUEUE_FILENAME = ".stalled-queue.json"
PENDING_HUB_RECOVERY_FILENAME = ".pending-hub-recovery.json"
WATCHDOG_STATE_FILENAME = ".quota-watchdog.json"
CONTINUE_REASON = (
    "Automatic recovery hook: previous turn hit a transient/capacity error. Resume cleanly from your "
    "last verified step; if a model or subagent hit 503/429, switch to an available healthy model and continue."
)


def _resolve_root(explicit_root: Optional[str] = None) -> Path:
    if explicit_root:
        return Path(explicit_root).expanduser().resolve()
    env_root = os.environ.get("AGY_PROFILES_DIR", "").strip()
    if env_root:
        return Path(env_root).expanduser().resolve()
    if Path("/Volumes/Dev").is_dir():
        return Path("/Volumes/Dev/.antigravity-profiles").resolve()
    return (Path.home() / ".antigravity-profiles").resolve()


def _resolve_agyp_bin() -> Optional[str]:
    env_bin = os.environ.get("AGYP_BIN", "").strip()
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    repo_bin = Path(__file__).resolve().parents[2] / "bin" / "agyp"
    if repo_bin.is_file() and os.access(str(repo_bin), os.X_OK):
        return str(repo_bin)
    home_bin = Path.home() / ".local" / "bin" / "agyp"
    if home_bin.is_file() and os.access(str(home_bin), os.X_OK):
        return str(home_bin)
    return shutil.which("agyp") or shutil.which("agy-profiles")


def _read_json_dict(fp: Path) -> Dict[str, Any]:
    if not fp.is_file() or fp.is_symlink():
        return {}
    try:
        data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _atomic_write_json(fp: Path, payload: Dict[str, Any]) -> None:
    fp.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".hook_", dir=str(fp.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, indent=2) + "\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, fp)
    except OSError:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def _read_tail_error_from_transcript(transcript_path: str) -> str:
    if not transcript_path:
        return ""
    tp = Path(transcript_path).expanduser()
    if not tp.is_file() or tp.is_symlink():
        return ""
    try:
        size = tp.stat().st_size
        with tp.open("rb") as fh:
            if size > 16384:
                fh.seek(size - 16384)
            chunk = fh.read(16384).decode("utf-8", errors="replace")
        for ln in reversed(chunk.splitlines()):
            s = ln.strip()
            if not s.startswith("{"):
                continue
            obj = json.loads(s)
            if isinstance(obj, dict) and obj.get("source") != "SYSTEM_SDK":
                return str(obj.get("error") or obj.get("content") or "")[:300]
    except (OSError, ValueError):
        return ""
    return ""


def _read_host_app_storage_email(home_dir: Path) -> str:
    data = _read_json_dict(home_dir / "Library" / "Application Support" / "Antigravity" / "app_storage.json")
    direct = data.get("agy.onboarding.lastLoginUsername")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    for k, v in data.items():
        if str(k).endswith("lastLoginUsername") and isinstance(v, str) and v.strip():
            return v.strip()
    for key in ("email", "username", "userEmail", "accountEmail"):
        val = data.get(key)
        if isinstance(val, str) and "@" in val:
            return val.strip()
    return ""


def _spawn_detached(cmd: List[str]) -> None:
    if os.environ.get("AGY_HOOK_NO_SPAWN") == "1":
        return
    try:
        subprocess.Popen(
            cmd,
            env=dict(os.environ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        pass


def handle_hook_event(
    payload: Dict[str, Any],
    *,
    event: Optional[str] = None,
    root_dir: Optional[Path] = None,
    home_dir: Optional[Path] = None,
    now_ts: Optional[float] = None,
) -> Dict[str, Any]:
    hook_event = str(event or payload.get("hookEventName") or "").strip()
    root = (root_dir or _resolve_root()).resolve()
    home = (home_dir or Path.home()).resolve()
    now_epoch = float(time.time() if now_ts is None else now_ts)
    agyp_bin = _resolve_agyp_bin()

    if hook_event == "Stop":
        term = str(payload.get("terminationReason") or "").upper()
        if term == "USER_CANCELED":
            return {}
        cid = str(payload.get("conversationId") or "").strip()
        err_text = str(payload.get("error") or "").strip()
        if not err_text and cid:
            err_text = _read_tail_error_from_transcript(str(payload.get("transcriptPath") or ""))

        is_quota = bool(QUOTA_OR_AUTH_RE.search(err_text))
        is_transient = bool(CAPACITY_OR_TRANSIENT_RE.search(err_text)) or (term == "ERROR" and not is_quota)
        if not (term == "ERROR" or is_quota or is_transient):
            return {}

        if cid:
            q_fp = root / STALLED_QUEUE_FILENAME
            queue = _read_json_dict(q_fp)
            queue[cid] = {
                "cascade_id": cid,
                "termination_reason": term or "ERROR",
                "error": err_text[:240],
                "recorded_at_epoch": now_epoch,
            }
            _atomic_write_json(q_fp, queue)

        if is_quota:
            if agyp_bin:
                _spawn_detached([agyp_bin, "--root", str(root), "watchdog", "--once", "--json"])
            return {}

        continuation_active = bool(payload.get("continuationActive"))
        if is_transient and not continuation_active and cid:
            ledger_fp = root / HOOK_LEDGER_FILENAME
            ledger = _read_json_dict(ledger_fp)
            entry = ledger.get(cid) if isinstance(ledger.get(cid), dict) else {}
            recent = [float(t) for t in (entry.get("ts") or []) if now_epoch - float(t) < 600.0]
            if len(recent) < 2:
                recent.append(now_epoch)
                ledger[cid] = {"ts": recent}
                _atomic_write_json(ledger_fp, ledger)
                return {"decision": "continue", "reason": CONTINUE_REASON}
        return {}

    if hook_event in ("SessionStart", "PreInvocation"):
        wd_state = _read_json_dict(root / WATCHDOG_STATE_FILENAME)
        auth_state = (((wd_state.get("desktop_retry_ledger") or {}).get("__auth_state__") or {}).get("host") or {})
        prev_email = str(auth_state.get("email") or "").strip()
        cur_email = _read_host_app_storage_email(home)
        email_changed = bool(prev_email and cur_email and prev_email != cur_email)

        pending_map = _read_json_dict(root / PENDING_HUB_RECOVERY_FILENAME)
        stalled_map = _read_json_dict(root / STALLED_QUEUE_FILENAME)
        has_pending = bool(pending_map or stalled_map)

        if (email_changed or has_pending) and agyp_bin and os.environ.get("ANTIGRAVITY_LS_ADDRESS"):
            ledger_fp = root / HOOK_LEDGER_FILENAME
            ledger = _read_json_dict(ledger_fp)
            last_rec = float(ledger.get("__last_session_recover_epoch__") or 0.0)
            cooldown = 15.0 if email_changed else 60.0
            if now_epoch - last_rec >= cooldown:
                ledger["__last_session_recover_epoch__"] = now_epoch
                _atomic_write_json(ledger_fp, ledger)
                cmd = [agyp_bin, "--root", str(root), "recover"]
                if email_changed:
                    cmd.append("--reset-ledger")
                cmd.append("--json")
                _spawn_detached(cmd)
        return {}

    return {}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Antigravity recovery hook for agy-profiles.")
    parser.add_argument("--event", default=None)
    parser.add_argument("--root", default=None)
    args, _ = parser.parse_known_args(argv)
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
    except (OSError, ValueError):
        payload = {}
    root_dir = _resolve_root(args.root)
    result = handle_hook_event(payload, event=args.event, root_dir=root_dir)
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
