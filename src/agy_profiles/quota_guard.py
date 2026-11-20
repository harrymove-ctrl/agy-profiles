"""Read-only Host quota-exhaustion detector, Antigravity Desktop Hub 5-hour quota auto-retry engine, and backup failover watchdog."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

from agy_profiles.config import atomic_write_json, ensure_within_root
from agy_profiles.evidence import compute_sha256, utc_now_iso
from agy_profiles.process_guard import command_matches_user_data_dir, list_all_processes

try:
    import pwd
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore[assignment]

QUOTA_EXHAUSTED_LINE_RE = re.compile(
    r"(?:"
    r"INSUFFICIENT_G1_CREDITS_BALANCE"
    r"|Quota\s+exhausted"
    r"|out\s+of\s+(?:credits|quota)"
    r"|(?:RESOURCE_EXHAUSTED|resource_exhausted).*(?:quota|credit|aicode|limit|exhausted|429)"
    r"|(?:quota|credit|aicode|429).*(?:RESOURCE_EXHAUSTED|resource_exhausted)"
    r")",
    re.IGNORECASE,
)

IGNORED_LOG_NOISE_RE = re.compile(
    r"(?:runner\.go:|Monitor\s+sir_|severe_internal_risks|Individual\s+quota\s+reached|quota_pause\.go:|native\s+swarm:)",
    re.IGNORECASE,
)

CSRF_TOKEN_RE = re.compile(r"--csrf_token(?:=|\s+)([A-Za-z0-9._-]+)")
HTTPS_URL_PORT_RE = re.compile(r"https://127\.0\.0\.1:(\d+)")
LSOF_LISTEN_PORT_RE = re.compile(r"127\.0\.0\.1:(\d+)\s+\(LISTEN\)")
AUTH_OR_MODEL_ERROR_RE = re.compile(
    r"(?:unknown\s+model\s+key|failed\s+to\s+construct\s+executor|not\s+logged\s+into\s+antigravity|token\s+source|unauthenticated)",
    re.IGNORECASE,
)

DEFAULT_RETRY_COOLDOWN_SEC = 300
MAX_ATTEMPTS_PER_STALL = 5
MAX_ATTEMPTS_PER_STEP = MAX_ATTEMPTS_PER_STALL
UNAVAILABLE_MODEL_NEVER_PICK = {"MODEL_PLACEHOLDER_M26"}
DEFAULT_CONTINUATION_PROMPT = (
    "Quota is refreshed. Continue from where you left off and wake any paused workers."
)
AUTH_RECOVERY_CONTINUATION_PROMPT = (
    "Antigravity session or auth refreshed after an execution error. Resume your active task from where you left off, "
    "check whether any background tasks, /schedule timers, or subagents stopped, re-arm them if needed, and continue."
)


def _resolve_retry_cooldown_sec(cooldown_sec: Optional[int] = None) -> int:
    """Resolve auto-retry cooldown seconds (default 300s / 5m, configurable via AGY_AUTO_RETRY_COOLDOWN_SEC)."""
    if cooldown_sec is not None:
        return max(1, int(cooldown_sec))
    raw_env = os.environ.get("AGY_AUTO_RETRY_COOLDOWN_SEC", "").strip()
    if raw_env:
        try:
            return max(30, int(raw_env))
        except ValueError:
            pass
    return DEFAULT_RETRY_COOLDOWN_SEC


def _os_user_home() -> Path:
    """Return the real macOS/POSIX user home directory from getpwuid."""
    if pwd is not None:
        try:
            return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
        except (KeyError, OSError):
            pass
    return Path.home().resolve()


def _is_real_host_context(ctx: Any) -> bool:
    """Return True when ctx targets the live macOS host rather than an isolated unit-test fake_home."""
    raw_home = getattr(ctx, "real_home", None)
    if raw_home is None:
        return True
    try:
        return Path(raw_home).resolve() == _os_user_home()
    except OSError:
        return False


def _resolve_port_from_devtools_file(app_support_dir: Path) -> Optional[int]:
    """Read DevToolsActivePort in app_support_dir and inspect /json/list to find the Hub HTTPS port."""
    port_file = app_support_dir / "DevToolsActivePort"
    if not port_file.is_file() or port_file.is_symlink():
        return None
    try:
        lines = port_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        if not lines:
            return None
        cdp_port = int(lines[0].strip())
        req = urllib.request.Request(
            "http://127.0.0.1:{}/json/list".format(cdp_port),
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            targets = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(targets, list):
            for t in targets:
                if not isinstance(t, dict):
                    continue
                url = str(t.get("url") or "")
                m = HTTPS_URL_PORT_RE.search(url)
                if m:
                    return int(m.group(1))
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return None


def _resolve_port_from_lsof(ls_pid: int) -> Optional[int]:
    """Query lsof for the first loopback TCP LISTEN port of language_server PID."""
    lsof_bin = "/usr/sbin/lsof" if os.path.isfile("/usr/sbin/lsof") else "lsof"
    try:
        proc = subprocess.run(
            [lsof_bin, "-a", "-p", str(ls_pid), "-iTCP", "-sTCP:LISTEN", "-P", "-n"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        for line in (proc.stdout or "").splitlines():
            m = LSOF_LISTEN_PORT_RE.search(line)
            if m:
                return int(m.group(1))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


def discover_desktop_hub_servers(
    root: Path,
    real_home: Optional[Path] = None,
    ps_rows: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Discover running Antigravity Desktop Hub (not IDE) language_server instances across Host and profiles."""
    host_home = (real_home if real_home is not None else _os_user_home()).resolve()
    rows = ps_rows if ps_rows is not None else list_all_processes()
    by_pid: Dict[int, Dict[str, Any]] = {int(r["pid"]): r for r in rows if "pid" in r}

    profile_dirs: List[Tuple[str, Path, Path, Path]] = []
    if root.is_dir():
        try:
            for entry in sorted(root.iterdir()):
                if not entry.is_dir() or entry.name.startswith(".") or entry.name == "logs":
                    continue
                data_dir = entry / "data"
                app_support = data_dir / "Antigravity"
                brain_dir = entry / "home" / ".gemini" / "antigravity" / "brain"
                profile_dirs.append((entry.name, data_dir, app_support, brain_dir))
        except OSError:
            pass

    servers: List[Dict[str, Any]] = []
    for r in rows:
        cmd = str(r.get("command") or "")
        if "language_server" not in cmd or "--subclient_type hub" not in cmd:
            continue
        m_tok = CSRF_TOKEN_RE.search(cmd)
        if not m_tok:
            continue
        csrf_token = m_tok.group(1)
        ls_pid = int(r["pid"])
        ppid = int(r.get("ppid") or 0)
        parent_cmd = str((by_pid.get(ppid) or {}).get("command") or "")

        scope = "host"
        app_support_dir = host_home / "Library" / "Application Support" / "Antigravity"
        brain_dir = host_home / ".gemini" / "antigravity" / "brain"

        for slug, data_dir, prof_app_support, prof_brain in profile_dirs:
            data_dir_str = str(data_dir.resolve())
            app_support_str = str(prof_app_support.resolve())
            if (
                command_matches_user_data_dir(parent_cmd, data_dir_str)
                or command_matches_user_data_dir(parent_cmd, app_support_str)
                or command_matches_user_data_dir(cmd, data_dir_str)
                or command_matches_user_data_dir(cmd, app_support_str)
            ):
                scope = slug
                app_support_dir = prof_app_support
                brain_dir = prof_brain
                break

        port = _resolve_port_from_devtools_file(app_support_dir)
        if port is None and ps_rows is None:
            port = _resolve_port_from_lsof(ls_pid)
        if port is None:
            continue

        servers.append(
            {
                "scope": scope,
                "pid": ls_pid,
                "ppid": ppid,
                "port": port,
                "csrf_token": csrf_token,
                "brain_dir": str(brain_dir),
            }
        )
    return servers


def _call_hub_ls_rpc(
    port: int,
    csrf_token: str,
    method: str,
    body: Optional[Dict[str, Any]] = None,
    timeout: float = 4.0,
) -> Dict[str, Any]:
    """Invoke a Connect-RPC method on a local Antigravity Desktop Hub language_server over HTTPS."""
    ssl_ctx = ssl._create_unverified_context()
    url = "https://127.0.0.1:{}/exa.language_server_pb.LanguageServerService/{}".format(int(port), method)
    req = urllib.request.Request(
        url,
        data=json.dumps(body if body is not None else {}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
            "x-codeium-csrf-token": csrf_token,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw.strip() else {}


def parse_quota_summary_buckets(quota_resp: Dict[str, Any], user_status_resp: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Weekly Limit, Five Hour Limit, and preferred available planModel from Hub RPC responses."""
    user_status = (user_status_resp.get("userStatus") or {}) if isinstance(user_status_resp, dict) else {}
    email = str(user_status.get("email") or "")
    tier_name = str(((user_status.get("userTier") or {}).get("name")) or "")

    groups = (((quota_resp or {}).get("response") or {}).get("groups")) or []
    buckets_by_id: Dict[str, Dict[str, Any]] = {}
    for grp in groups:
        if not isinstance(grp, dict):
            continue
        for b in grp.get("buckets") or []:
            if not isinstance(b, dict):
                continue
            bid = str(b.get("bucketId") or "")
            if bid:
                buckets_by_id[bid] = {
                    "bucket_id": bid,
                    "display_name": str(b.get("displayName") or ""),
                    "window": str(b.get("window") or ""),
                    "remaining_fraction": float(b["remainingFraction"]) if "remainingFraction" in b else 0.0,
                    "reset_time": str(b.get("resetTime") or ""),
                }

    gem_weekly = buckets_by_id.get("gemini-weekly")
    gem_5h = buckets_by_id.get("gemini-5h")
    argon_weekly = buckets_by_id.get("gemini-argon-wtu-weekly")
    third_party_5h = buckets_by_id.get("3p-5h")

    weekly_rem = gem_weekly["remaining_fraction"] if gem_weekly is not None else None
    five_hour_rem = gem_5h["remaining_fraction"] if gem_5h is not None else None
    five_hour_reset = gem_5h["reset_time"] if gem_5h is not None else None
    argon_rem = argon_weekly["remaining_fraction"] if argon_weekly is not None else None

    # Determine if 5-hour quota is exhausted while Weekly Limit still has balance.
    five_hour_exhausted_only = bool(
        five_hour_rem is not None
        and five_hour_rem <= 0.0
        and (weekly_rem is None or weekly_rem > 0.0)
    )

    # Pick preferred planModel placeholder so resumed turns never fail with missing model config.
    cascade_cfg = user_status.get("cascadeModelConfigData") or {}
    available_models: Dict[str, Optional[float]] = {}
    has_model_list = isinstance(cascade_cfg, dict) and "clientModelConfigs" in cascade_cfg and isinstance(
        cascade_cfg.get("clientModelConfigs"), list
    )
    if has_model_list:
        for cfg in cascade_cfg.get("clientModelConfigs") or []:
            if not isinstance(cfg, dict):
                continue
            model_id = str(((cfg.get("modelOrAlias") or {}).get("model")) or "").strip()
            if not model_id:
                continue
            qi = cfg.get("quotaInfo") or {}
            rem_val: Optional[float] = None
            if isinstance(qi, dict) and qi.get("remainingFraction") is not None:
                try:
                    rem_val = float(qi["remainingFraction"])
                except (TypeError, ValueError):
                    rem_val = None
            available_models[model_id] = rem_val
        models_loaded = len(available_models) > 0
    else:
        models_loaded = True

    default_model = str(
        (((cascade_cfg.get("defaultOverrideModelConfig") or {}).get("modelOrAlias") or {}).get("model"))
        or "MODEL_PLACEHOLDER_M427"
    )
    preferred_model = default_model
    can_dispatch_now = bool(email) and models_loaded
    if five_hour_exhausted_only:
        if argon_rem is not None and argon_rem > 0.0:
            preferred_model = "MODEL_PLACEHOLDER_M417"
            can_dispatch_now = bool(email) and models_loaded
        elif third_party_5h is not None and third_party_5h["remaining_fraction"] > 0.0:
            preferred_model = "MODEL_PLACEHOLDER_M402"
            can_dispatch_now = bool(email) and models_loaded
        else:
            can_dispatch_now = False
    elif weekly_rem is not None and weekly_rem <= 0.0:
        if argon_rem is not None and argon_rem > 0.0:
            preferred_model = "MODEL_PLACEHOLDER_M417"
            can_dispatch_now = bool(email) and models_loaded
        else:
            can_dispatch_now = False

    if can_dispatch_now and available_models:
        pref_rem = available_models.get(preferred_model)
        if preferred_model not in available_models or (pref_rem is not None and pref_rem <= 0.0):
            for cand_id, cand_rem in available_models.items():
                if cand_id in UNAVAILABLE_MODEL_NEVER_PICK:
                    continue
                if cand_rem is None or cand_rem > 0.0:
                    preferred_model = cand_id
                    break

    weekly_exhausted = bool(
        weekly_rem is not None
        and weekly_rem <= 0.0
        and (argon_rem is None or argon_rem <= 0.0)
    )

    return {
        "signed_in": bool(email),
        "email": email,
        "tier": tier_name,
        "weekly_remaining": weekly_rem,
        "weekly_reset_time": gem_weekly["reset_time"] if gem_weekly is not None else None,
        "five_hour_remaining": five_hour_rem,
        "five_hour_reset_time": five_hour_reset,
        "argon_weekly_remaining": argon_rem,
        "five_hour_exhausted_while_weekly_available": five_hour_exhausted_only,
        "weekly_exhausted": weekly_exhausted,
        "can_dispatch_now": can_dispatch_now,
        "models_loaded": models_loaded,
        "available_models": available_models,
        "preferred_plan_model": preferred_model,
        "buckets": buckets_by_id,
    }


def select_plan_model_for_conversation(
    quota_info: Dict[str, Any],
    conv_generator_model: Optional[str],
) -> str:
    """Keep the conversation's own model when available on the active account, else fall back safely."""
    available = quota_info.get("available_models") or {}
    gen_model = str(conv_generator_model or "").strip()
    if gen_model and isinstance(available, dict) and available:
        if gen_model in available and gen_model not in UNAVAILABLE_MODEL_NEVER_PICK:
            rem = available.get(gen_model)
            if rem is None or float(rem) > 0.0:
                return gen_model
    return str(quota_info.get("preferred_plan_model") or "MODEL_PLACEHOLDER_M427")


def classify_stall_root_cause(item: Dict[str, Any], quota_info: Dict[str, Any]) -> str:
    """Map a stalled conversation and live account quota state to a canonical RCA category."""
    if quota_info.get("weekly_exhausted"):
        return "WEEKLY_QUOTA_EXHAUSTED"
    if quota_info.get("five_hour_exhausted_while_weekly_available"):
        return "FIVE_HOUR_QUOTA_PAUSE"
    stall_kind = str(item.get("stall_kind") or "")
    stall_reason = str(item.get("stall_reason") or "").lower()
    gen_model = str(item.get("generator_model") or "").strip()
    avail = quota_info.get("available_models") or {}
    if stall_kind == "auth_or_model_error":
        if gen_model and isinstance(avail, dict) and avail and gen_model not in avail:
            return "ACCOUNT_MODEL_MISSING"
        return "AUTH_LOGIN_MODEL_GAP"
    if "goaway" in stall_reason or "stream" in stall_reason or "deadline" in stall_reason:
        return "HTTP2_STREAM_DROP"
    if stall_kind in ("subagent_or_swarm_quota", "interrupted_after_tool"):
        return "TOOL_HOOK_INTERRUPT"
    return "EXECUTION_ERROR"


def build_incident_stories(hubs_report: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse simultaneous downstream stalls sharing (scope, root_cause_class) into causal stories."""
    grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
    order: List[Tuple[str, str]] = []
    for hub in hubs_report:
        if not isinstance(hub, dict):
            continue
        scope = str(hub.get("scope") or "host")
        resumed_ids = {
            str(r.get("cascade_id"))
            for r in (hub.get("resumed_conversations") or [])
            if isinstance(r, dict) and r.get("cascade_id")
        }
        for item in hub.get("stalled_conversations") or []:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("cascade_id") or "")
            cls = str(item.get("root_cause_class") or "EXECUTION_ERROR")
            key = (scope, cls)
            if key not in grouped:
                order.append(key)
                grouped[key] = {
                    "scope": scope,
                    "root_cause_class": cls,
                    "affected_count": 0,
                    "resumed_count": 0,
                    "cascade_ids": [],
                }
            grp = grouped[key]
            grp["affected_count"] += 1
            if cid and cid not in grp["cascade_ids"]:
                grp["cascade_ids"].append(cid)
            if cid and cid in resumed_ids:
                grp["resumed_count"] += 1
    stories: List[Dict[str, Any]] = []
    for key in order:
        grp = grouped[key]
        noun = "conversation" if grp["affected_count"] == 1 else "conversations"
        grp["summary"] = "{} {} affected by {} on {}; {} resumed".format(
            grp["affected_count"],
            noun,
            grp["root_cause_class"],
            grp["scope"],
            grp["resumed_count"],
        )
        stories.append(grp)
    return stories


def append_recovery_audit_receipt(root_dir: Path, report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Append a 0o600 hash-chained JSONL recovery receipt without tokens, emails, or prompt text."""
    if report.get("dry_run") or int(report.get("resumed_total") or 0) <= 0:
        return None
    logs_dir = ensure_within_root(root_dir, root_dir / "logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(logs_dir), 0o700)
    receipt_path = ensure_within_root(root_dir, logs_dir / "recovery-audit.jsonl")
    if receipt_path.is_symlink():
        return None

    prev_hash = "GENESIS"
    if receipt_path.is_file():
        try:
            lines = [ln.strip() for ln in receipt_path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
            if lines:
                last_obj = json.loads(lines[-1])
                if isinstance(last_obj, dict) and last_obj.get("receipt_hash"):
                    prev_hash = str(last_obj["receipt_hash"])
        except (OSError, ValueError):
            prev_hash = "GENESIS"

    resumed_rows = [
        {
            "scope": str(r.get("scope") or "host"),
            "cascade_id": str(r.get("cascade_id") or ""),
            "stall_kind": str(r.get("stall_kind") or ""),
            "root_cause_class": str(r.get("root_cause_class") or "EXECUTION_ERROR"),
            "plan_model": str(r.get("plan_model") or ""),
            "mode": str(r.get("mode") or ""),
            "attempt": int(r.get("attempt") or 1),
        }
        for r in (report.get("resumed_conversations") or [])
        if isinstance(r, dict)
    ]
    payload: Dict[str, Any] = {
        "recorded_at": utc_now_iso(),
        "prev_hash": prev_hash,
        "resumed_total": int(report.get("resumed_total") or 0),
        "stalled_total": int(report.get("stalled_total") or 0),
        "incident_stories": report.get("incident_stories") or [],
        "resumed": resumed_rows,
    }
    receipt_hash = compute_sha256(payload)
    record = {**payload, "receipt_hash": receipt_hash}
    with receipt_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    try:
        os.chmod(str(receipt_path), 0o600)
    except OSError:
        pass
    return record


def _parse_iso_epoch(iso_str: str) -> Optional[float]:
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def find_stalled_desktop_conversations(
    summaries: Dict[str, Any],
    brain_dir: Path,
    now_epoch: Optional[float] = None,
    lookback_hours: float = 12.0,
    min_idle_age_sec: float = 20.0,
    rpc_caller: Optional[Callable[..., Dict[str, Any]]] = None,
    port: Optional[int] = None,
    csrf_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Detect IDLE Antigravity Desktop Hub conversations stalled on auth/model errors, RPC errors, 5h quota, or stream drops."""
    now_ts = float(time.time() if now_epoch is None else now_epoch)
    max_age_sec = float(lookback_hours) * 3600.0
    can_query_rpc = rpc_caller is not None and port is not None and bool(csrf_token)

    running_ids = {
        str(cid)
        for cid, s in (summaries or {}).items()
        if isinstance(s, dict) and s.get("status") != "CASCADE_RUN_STATUS_IDLE"
    }

    candidates: List[Dict[str, Any]] = []
    stalled_root_ids: set[str] = set()

    # Pass 1: inspect root conversations first, then child conversations in Pass 2.
    ordered_items = sorted(
        (summaries or {}).items(),
        key=lambda kv: (
            1 if ((kv[1].get("trajectoryMetadata") or {}).get("parentConversationId")) else 0,
            -float(_parse_iso_epoch(str((kv[1] or {}).get("lastModifiedTime") or "")) or 0.0),
        ),
    )

    for cid, s in ordered_items:
        if not isinstance(s, dict):
            continue
        if s.get("status") != "CASCADE_RUN_STATUS_IDLE" or s.get("killed"):
            continue
        term = str(s.get("latestExecutorTerminationReason") or "")
        if term == "EXECUTOR_TERMINATION_REASON_USER_CANCELED":
            continue

        meta = s.get("trajectoryMetadata") or {}
        parent_id = str(meta.get("parentConversationId") or "")
        root_id = str(meta.get("rootConversationId") or cid)
        is_subagent = bool(parent_id)

        if is_subagent:
            if parent_id in running_ids or root_id in running_ids:
                continue
            if parent_id in stalled_root_ids or root_id in stalled_root_ids:
                continue

        mtime_epoch = _parse_iso_epoch(str(s.get("lastModifiedTime") or ""))
        if mtime_epoch is None:
            continue
        idle_age = now_ts - mtime_epoch
        if idle_age < min(3.0, min_idle_age_sec):
            continue
        effective_max_age = min(max_age_sec, 7200.0) if is_subagent else max_age_sec
        if idle_age > effective_max_age:
            continue

        t_path = brain_dir / str(cid) / ".system_generated" / "logs" / "transcript.jsonl"
        if t_path.is_symlink():
            continue
        has_transcript = t_path.is_file()
        if not has_transcript and not can_query_rpc:
            continue

        steps: List[Dict[str, Any]] = []
        if has_transcript:
            try:
                size = int(t_path.stat().st_size)
                with t_path.open("rb") as fh:
                    fh.seek(max(0, size - 32768))
                    raw_tail = fh.read().decode("utf-8", errors="replace")
                for ln in raw_tail.splitlines():
                    stripped = ln.strip()
                    if not stripped.startswith("{"):
                        continue
                    try:
                        parsed = json.loads(stripped)
                        if isinstance(parsed, dict):
                            steps.append(parsed)
                    except ValueError:
                        continue
            except OSError:
                if not can_query_rpc:
                    continue

        non_sdk = [st for st in steps if st.get("source") != "SYSTEM_SDK"]
        if not non_sdk and not can_query_rpc:
            continue

        last = non_sdk[-1] if non_sdk else {}
        last_type = str(last.get("type") or "")
        last_src = str(last.get("source") or "")
        last_status = str(last.get("status") or "")
        last_content = str(last.get("content") or "")
        last_error = str(last.get("error") or "")
        has_tools = bool(last.get("tool_calls"))
        step_count = int(s.get("stepCount") or last.get("step_index") or len(steps))

        last_good_step = 0
        for st in non_sdk:
            if st.get("type") == "PLANNER_RESPONSE" and st.get("status") == "DONE":
                try:
                    sidx = int(st.get("step_index") or 0)
                    if sidx > last_good_step:
                        last_good_step = sidx
                except (TypeError, ValueError):
                    pass

        stall_kind: Optional[str] = None
        stall_reason: Optional[str] = None
        needs_prompt_bypass = False
        conv_generator_model: Optional[str] = None

        if non_sdk:
            if last_type == "ERROR_MESSAGE":
                stall_kind = "error_message"
                stall_reason = last_error[:160] or "API or stream error step"
                needs_prompt_bypass = bool(
                    term == "EXECUTOR_TERMINATION_REASON_TERMINAL_CUSTOM_HOOK"
                    or "Individual quota reached" in last_error
                    or "RESOURCE_EXHAUSTED" in last_error
                    or AUTH_OR_MODEL_ERROR_RE.search(last_error)
                )
            elif last_src == "SYSTEM" and last_type == "SYSTEM_MESSAGE":
                stall_kind = "subagent_or_swarm_quota"
                stall_reason = last_content.replace("\n", " ")[:160]
                needs_prompt_bypass = True
            elif last_src == "USER_EXPLICIT" and last_type == "USER_INPUT":
                stall_kind = "unhandled_user_input"
                stall_reason = "User input received without planner response"
                needs_prompt_bypass = False
            elif term == "EXECUTOR_TERMINATION_REASON_ERROR" and not (
                last_type == "PLANNER_RESPONSE" and not has_tools and last_status == "DONE"
            ):
                stall_kind = "executor_error"
                stall_reason = last_error[:160] or "Executor terminated with error on {}".format(last_type)
                needs_prompt_bypass = False
            elif (
                not is_subagent
                and last_type == "GENERIC"
                and "Waiting for a message that calls on you by name" not in last_content
                and term not in ("EXECUTOR_TERMINATION_REASON_NO_TOOL_CALL", "EXECUTOR_TERMINATION_REASON_TERMINAL_STEP_TYPE")
            ):
                stall_kind = "interrupted_after_tool"
                stall_reason = "Tool step completed without subsequent planner response ({})".format(term)
                needs_prompt_bypass = term == "EXECUTOR_TERMINATION_REASON_TERMINAL_CUSTOM_HOOK"

        if can_query_rpc and step_count > 0:
            try:
                rpc_resp = rpc_caller(  # type: ignore[misc]
                    int(port),  # type: ignore[arg-type]
                    str(csrf_token),
                    "GetCascadeTrajectorySteps",
                    {"cascadeId": str(cid), "stepOffset": max(0, step_count - 3)},
                )
            except Exception:
                rpc_resp = {}
            rpc_steps = (rpc_resp or {}).get("steps") if isinstance(rpc_resp, dict) else []
            if isinstance(rpc_steps, list) and rpc_steps:
                for step in reversed(rpc_steps):
                    if not isinstance(step, dict):
                        continue
                    gm = str(((step.get("metadata") or {}).get("generatorModel")) or "").strip()
                    if gm:
                        conv_generator_model = gm
                        break
                for step in rpc_steps:
                    if not isinstance(step, dict):
                        continue
                    if (
                        step.get("type") == "CORTEX_STEP_TYPE_PLANNER_RESPONSE"
                        and step.get("status") == "CORTEX_STEP_STATUS_DONE"
                    ):
                        info = ((step.get("metadata") or {}).get("sourceTrajectoryStepInfo")) or {}
                        try:
                            sidx = int(info.get("stepIndex") or 0)
                            if sidx > last_good_step:
                                last_good_step = sidx
                        except (TypeError, ValueError):
                            pass
                rpc_last = rpc_steps[-1]
                if isinstance(rpc_last, dict) and rpc_last.get("type") == "CORTEX_STEP_TYPE_ERROR_MESSAGE":
                    err_obj = (rpc_last.get("errorMessage") or {}).get("error") or {}
                    err_msg = str(
                        err_obj.get("shortError")
                        or err_obj.get("modelErrorMessage")
                        or err_obj.get("userErrorMessage")
                        or "Agent execution terminated due to error."
                    )
                    stall_kind = "auth_or_model_error" if AUTH_OR_MODEL_ERROR_RE.search(err_msg) else "rpc_error_message"
                    stall_reason = err_msg[:180]
                    needs_prompt_bypass = True

        if stall_kind is None:
            continue
        if idle_age < min_idle_age_sec and stall_kind not in ("auth_or_model_error", "rpc_error_message", "error_message"):
            continue

        if not is_subagent:
            stalled_root_ids.add(str(cid))

        candidates.append(
            {
                "cascade_id": str(cid),
                "title": str(s.get("summary") or (s.get("annotations") or {}).get("title") or cid),
                "is_subagent": is_subagent,
                "parent_id": parent_id or None,
                "step_count": step_count,
                "last_good_step": last_good_step,
                "generator_model": conv_generator_model,
                "termination_reason": term,
                "stall_kind": stall_kind,
                "stall_reason": stall_reason,
                "needs_prompt_bypass": needs_prompt_bypass,
                "idle_age_sec": round(idle_age, 1),
            }
        )

    return candidates


def resume_stalled_desktop_conversation(
    port: int,
    csrf_token: str,
    cascade_id: str,
    plan_model: str = "MODEL_PLACEHOLDER_M427",
    use_continuation_prompt: bool = False,
    continuation_text: str = DEFAULT_CONTINUATION_PROMPT,
    rpc_caller: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Resume a stalled Antigravity Desktop Hub conversation via Connect-RPC SendUserCascadeMessage."""
    caller = rpc_caller or _call_hub_ls_rpc
    items: List[Dict[str, Any]] = [{"text": continuation_text}] if use_continuation_prompt else []
    payload: Dict[str, Any] = {
        "cascadeId": cascade_id,
        "items": items,
        "cascadeConfig": {
            "plannerConfig": {
                "supportsLatexRendering": True,
                "planModel": plan_model,
                "toolConfig": {
                    "runCommand": {
                        "autoCommandConfig": {
                            "autoExecutionPolicy": 2,
                        }
                    }
                },
            },
            "conversationHistoryConfig": {},
        },
    }
    resp = caller(port, csrf_token, "SendUserCascadeMessage", payload)
    return {
        "cascade_id": cascade_id,
        "mode": "continuation_prompt" if use_continuation_prompt else "empty_retry",
        "plan_model": plan_model,
        "response": resp,
    }


def poll_desktop_hub_auto_retry(
    ctx: Any,
    ledger: Optional[Dict[str, Any]] = None,
    ps_rows: Optional[List[Dict[str, Any]]] = None,
    rpc_caller: Optional[Callable[..., Dict[str, Any]]] = None,
    now_epoch: Optional[float] = None,
    cooldown_sec: Optional[int] = None,
    auth_state: Optional[Dict[str, Any]] = None,
    scope_filter: Optional[str] = None,
    dry_run: bool = False,
    reset_ledger: bool = False,
    lookback_hours: float = 12.0,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Inspect all running Antigravity Desktop Hub servers and auto-resume stalled or errored conversations."""
    now_ts = float(time.time() if now_epoch is None else now_epoch)
    eff_cooldown = _resolve_retry_cooldown_sec(cooldown_sec)
    next_ledger: Dict[str, Any] = dict(ledger or {})

    raw_auth = next_ledger.get("__auth_state__")
    prev_auth_map: Dict[str, Dict[str, Any]] = dict(raw_auth) if isinstance(raw_auth, dict) else {}
    if isinstance(auth_state, dict):
        for k, v in auth_state.items():
            if isinstance(v, dict):
                prev_auth_map[str(k)] = dict(v)
    cur_auth_map: Dict[str, Dict[str, Any]] = {k: dict(v) for k, v in prev_auth_map.items() if isinstance(v, dict)}

    # Prune ledger entries older than 24h so state file stays compact.
    for k in list(next_ledger.keys()):
        if k == "__auth_state__":
            continue
        entry = next_ledger.get(k)
        if not isinstance(entry, dict) or (now_ts - float(entry.get("updated_at_epoch") or 0.0)) > 86400.0:
            next_ledger.pop(k, None)

    if ps_rows is None and rpc_caller is None and not _is_real_host_context(ctx):
        return (
            {
                "checked_at": utc_now_iso(),
                "cooldown_sec": eff_cooldown,
                "dry_run": bool(dry_run),
                "hubs_inspected": [],
                "incident_stories": [],
                "resumed_conversations": [],
                "resumed_total": 0,
                "stalled_total": 0,
                "host_five_hour_exhausted_only": False,
                "host_weekly_exhausted": False,
            },
            next_ledger,
        )

    caller = rpc_caller or _call_hub_ls_rpc
    servers = discover_desktop_hub_servers(Path(ctx.root).resolve(), ctx.real_home, ps_rows=ps_rows)
    hubs_report: List[Dict[str, Any]] = []
    resumed_all: List[Dict[str, Any]] = []
    stalled_total = 0
    host_5h_exhausted_only = False
    host_5h_reset_time: Optional[str] = None
    host_weekly_exhausted = False
    host_weekly_reset_time: Optional[str] = None

    for srv in servers:
        scope = str(srv["scope"])
        if scope_filter and scope_filter != "all" and scope != scope_filter:
            continue
        port = int(srv["port"])
        token = str(srv["csrf_token"])
        brain_dir = Path(str(srv["brain_dir"]))
        try:
            user_st = caller(port, token, "GetUserStatus", {})
            traj_st = caller(port, token, "GetAllCascadeTrajectories", {})
        except (OSError, ValueError, urllib.error.URLError) as exc:
            hubs_report.append(
                {
                    "scope": scope,
                    "pid": srv["pid"],
                    "port": port,
                    "reachable": False,
                    "error": str(exc)[:160],
                }
            )
            continue

        try:
            quota_st = caller(port, token, "RetrieveUserQuotaSummary", {})
        except (OSError, ValueError, urllib.error.URLError):
            quota_st = {}

        quota_info = parse_quota_summary_buckets(quota_st, user_st)
        prev_scope_auth = prev_auth_map.get(scope) if isinstance(prev_auth_map.get(scope), dict) else {}
        cur_email = str(quota_info.get("email") or "")
        cur_signed_in = bool(quota_info.get("signed_in"))
        cur_can_dispatch = bool(quota_info.get("can_dispatch_now"))
        prev_email = str(prev_scope_auth.get("email") or "")
        prev_signed_in = prev_scope_auth.get("signed_in")
        prev_can_dispatch = prev_scope_auth.get("can_dispatch_now")

        auth_refreshed = bool(
            (prev_email and cur_email and prev_email != cur_email)
            or (prev_signed_in is False and cur_signed_in is True)
            or (prev_can_dispatch is False and cur_can_dispatch is True)
        )
        if not dry_run:
            cur_auth_map[scope] = {
                "email": cur_email,
                "signed_in": cur_signed_in,
                "can_dispatch_now": cur_can_dispatch,
                "models_loaded": bool(quota_info.get("models_loaded")),
                "updated_at_epoch": now_ts,
            }
            if auth_refreshed or reset_ledger:
                scope_prefix = "{}:".format(scope)
                for lk in [key for key in next_ledger if key != "__auth_state__" and key.startswith(scope_prefix)]:
                    next_ledger.pop(lk, None)

        if scope == "host":
            if quota_info["five_hour_exhausted_while_weekly_available"]:
                host_5h_exhausted_only = True
                host_5h_reset_time = quota_info.get("five_hour_reset_time")
            if quota_info["weekly_exhausted"]:
                host_weekly_exhausted = True
                host_weekly_reset_time = quota_info.get("weekly_reset_time")

        summaries = (traj_st.get("trajectorySummaries") or {}) if isinstance(traj_st, dict) else {}
        stalled = find_stalled_desktop_conversations(
            summaries,
            brain_dir,
            now_epoch=now_ts,
            lookback_hours=lookback_hours,
            rpc_caller=caller,
            port=port,
            csrf_token=token,
        )
        for item in stalled:
            item["root_cause_class"] = classify_stall_root_cause(item, quota_info)
        stalled_total += len(stalled)
        resumed_here: List[Dict[str, Any]] = []

        if quota_info["can_dispatch_now"] and not dry_run:
            for item in stalled:
                cid = str(item["cascade_id"])
                step_count = int(item["step_count"])
                last_good_step = int(item.get("last_good_step") or 0)
                ledger_key = "{}:{}".format(scope, cid)
                prev_entry = next_ledger.get(ledger_key) if isinstance(next_ledger.get(ledger_key), dict) else {}
                if auth_refreshed or reset_ledger:
                    attempts = 0
                    last_try = 0.0
                else:
                    attempts = int(prev_entry.get("attempts") or 0)
                    last_try = float(prev_entry.get("updated_at_epoch") or 0.0)
                    prev_good_step = int(prev_entry.get("last_good_step") or 0)
                    if last_good_step > prev_good_step:
                        attempts = 0

                if attempts >= MAX_ATTEMPTS_PER_STALL:
                    continue
                if attempts > 0 and (now_ts - last_try) < float(eff_cooldown):
                    continue

                # Use continuation prompt when required by quota_pause.go custom hook, RPC errors, or on retries.
                use_prompt = bool(item["needs_prompt_bypass"] or attempts >= 1)
                chosen_model = select_plan_model_for_conversation(quota_info, item.get("generator_model"))
                cont_text = (
                    AUTH_RECOVERY_CONTINUATION_PROMPT
                    if item["stall_kind"] in ("auth_or_model_error", "rpc_error_message")
                    else DEFAULT_CONTINUATION_PROMPT
                )
                try:
                    res_call = resume_stalled_desktop_conversation(
                        port=port,
                        csrf_token=token,
                        cascade_id=cid,
                        plan_model=chosen_model,
                        use_continuation_prompt=use_prompt,
                        continuation_text=cont_text,
                        rpc_caller=caller,
                    )
                    next_ledger[ledger_key] = {
                        "attempts": attempts + 1,
                        "updated_at_epoch": now_ts,
                        "last_step_count": step_count,
                        "last_good_step": last_good_step,
                        "mode": res_call["mode"],
                        "stall_kind": item["stall_kind"],
                        "root_cause_class": item["root_cause_class"],
                        "email": cur_email,
                    }
                    resumed_entry = {
                        "scope": scope,
                        "cascade_id": cid,
                        "title": item["title"],
                        "step_count": step_count,
                        "last_good_step": last_good_step,
                        "stall_kind": item["stall_kind"],
                        "root_cause_class": item["root_cause_class"],
                        "mode": res_call["mode"],
                        "plan_model": res_call["plan_model"],
                        "attempt": attempts + 1,
                    }
                    resumed_here.append(resumed_entry)
                    resumed_all.append(resumed_entry)
                except (OSError, ValueError, urllib.error.URLError):
                    continue

        hubs_report.append(
            {
                "scope": scope,
                "pid": srv["pid"],
                "port": port,
                "reachable": True,
                "signed_in": quota_info["signed_in"],
                "email": quota_info["email"],
                "models_loaded": quota_info["models_loaded"],
                "auth_refreshed": auth_refreshed,
                "cooldown_sec": eff_cooldown,
                "weekly_remaining": quota_info["weekly_remaining"],
                "five_hour_remaining": quota_info["five_hour_remaining"],
                "five_hour_reset_time": quota_info["five_hour_reset_time"],
                "argon_weekly_remaining": quota_info["argon_weekly_remaining"],
                "five_hour_exhausted_while_weekly_available": quota_info["five_hour_exhausted_while_weekly_available"],
                "can_dispatch_now": quota_info["can_dispatch_now"],
                "preferred_plan_model": quota_info["preferred_plan_model"],
                "stalled_count": len(stalled),
                "stalled_conversations": stalled,
                "resumed_conversations": resumed_here,
            }
        )

    if not dry_run:
        next_ledger["__auth_state__"] = cur_auth_map

    incident_stories = build_incident_stories(hubs_report)
    return (
        {
            "checked_at": utc_now_iso(),
            "cooldown_sec": eff_cooldown,
            "dry_run": bool(dry_run),
            "hubs_inspected": hubs_report,
            "incident_stories": incident_stories,
            "resumed_conversations": resumed_all,
            "resumed_total": len(resumed_all),
            "stalled_total": stalled_total,
            "host_five_hour_exhausted_only": host_5h_exhausted_only,
            "host_five_hour_reset_time": host_5h_reset_time,
            "host_weekly_exhausted": host_weekly_exhausted,
            "host_weekly_reset_time": host_weekly_reset_time,
        },
        next_ledger,
    )


def recover_desktop_sessions_once(
    ctx: Any,
    scope: str = "all",
    dry_run: bool = False,
    reset_ledger: bool = False,
    lookback_hours: float = 12.0,
    cooldown_sec: Optional[int] = None,
    ps_rows: Optional[List[Dict[str, Any]]] = None,
    rpc_caller: Optional[Callable[..., Dict[str, Any]]] = None,
    now_epoch: Optional[float] = None,
) -> Dict[str, Any]:
    """Inspect Desktop Hub sessions and resume errored or stalled conversations without profile failover."""
    root_dir = Path(ctx.root).resolve()
    root_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(root_dir), 0o700)
    state_file = ensure_within_root(root_dir, root_dir / ".quota-watchdog.json")

    prev_state: Dict[str, Any] = {}
    if state_file.is_file() and not state_file.is_symlink():
        try:
            loaded = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                prev_state = loaded
        except (OSError, ValueError):
            pass

    prev_ledger = prev_state.get("desktop_retry_ledger")
    desktop_retry, next_ledger = poll_desktop_hub_auto_retry(
        ctx,
        ledger=prev_ledger if isinstance(prev_ledger, dict) else {},
        ps_rows=ps_rows,
        rpc_caller=rpc_caller,
        now_epoch=now_epoch,
        cooldown_sec=cooldown_sec,
        scope_filter=scope,
        dry_run=dry_run,
        reset_ledger=reset_ledger,
        lookback_hours=lookback_hours,
    )

    if not dry_run:
        receipt = append_recovery_audit_receipt(root_dir, desktop_retry)
        if receipt is not None:
            desktop_retry["audit_receipt_hash"] = receipt["receipt_hash"]
        updated_state = dict(prev_state)
        updated_state["desktop_retry_ledger"] = next_ledger
        updated_state["last_desktop_auto_retry"] = {
            "checked_at": desktop_retry.get("checked_at"),
            "resumed_total": desktop_retry.get("resumed_total", 0),
            "stalled_total": desktop_retry.get("stalled_total", 0),
            "incident_stories": desktop_retry.get("incident_stories") or [],
            "resumed_conversations": desktop_retry.get("resumed_conversations") or [],
            "host_five_hour_exhausted_only": desktop_retry.get("host_five_hour_exhausted_only", False),
            "host_five_hour_reset_time": desktop_retry.get("host_five_hour_reset_time"),
        }
        updated_state["updated_at"] = utc_now_iso()
        atomic_write_json(state_file, updated_state, mode=0o600)

    return desktop_retry


def host_quota_log_paths(real_home: Optional[Path] = None) -> List[Path]:
    """Return Host Antigravity Hub and CLI log files to monitor for quota exhaustion."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    return [
        host_home / "Library" / "Logs" / "Antigravity" / "language_server.log",
        host_home / ".gemini" / "antigravity" / "cli.log",
        host_home / ".gemini" / "antigravity-cli" / "cli.log",
    ]


def snapshot_log_offsets(log_paths: List[Path]) -> Dict[str, int]:
    """Capture current EOF byte offsets so only newly emitted log lines trigger failover."""
    offsets: Dict[str, int] = {}
    for p in log_paths:
        key = str(p)
        try:
            if p.is_file() and not p.is_symlink():
                offsets[key] = int(p.stat().st_size)
        except OSError:
            continue
    return offsets


def scan_new_log_bytes_for_quota_exhaustion(
    log_paths: List[Path],
    offsets: Dict[str, int],
    initialize_at_eof: bool = True,
) -> Tuple[bool, Optional[str], Dict[str, int]]:
    """Read appended bytes since offsets and check for genuine Google quota exhaustion."""
    next_offsets = dict(offsets)
    matched_reason: Optional[str] = None

    for p in log_paths:
        key = str(p)
        if not p.is_file() or p.is_symlink():
            continue
        try:
            size = int(p.stat().st_size)
        except OSError:
            continue

        if key not in next_offsets:
            if initialize_at_eof:
                next_offsets[key] = size
                continue
            prev_off = max(0, size - 65536)
        else:
            prev_off = int(next_offsets[key])
            if size < prev_off:
                # Log file rotated or truncated; scan tail of new file.
                prev_off = max(0, size - 65536)

        next_offsets[key] = size
        if size <= prev_off or matched_reason is not None:
            continue

        read_start = max(prev_off, size - 262144)
        try:
            with p.open("rb") as fh:
                fh.seek(read_start)
                chunk = fh.read(size - read_start).decode("utf-8", errors="replace")
        except OSError:
            continue

        for line in chunk.splitlines():
            if IGNORED_LOG_NOISE_RE.search(line):
                continue
            if QUOTA_EXHAUSTED_LINE_RE.search(line):
                matched_reason = "{}: {}".format(p.name, line.strip()[:180])
                break

    return (matched_reason is not None), matched_reason, next_offsets


def poll_auto_failover_once(
    ctx: Any,
    call_tool_fn: Any,
    launch: bool = True,
    copy_prompt: bool = True,
    failover_on_5h: bool = True,
) -> Dict[str, Any]:
    """Check Host logs, auto-resume stalled Antigravity Desktop Hub conversations, and fail over when exhausted."""
    root_dir = Path(ctx.root).resolve()
    root_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(root_dir), 0o700)
    state_file = ensure_within_root(root_dir, root_dir / ".quota-watchdog.json")

    prev_state: Dict[str, Any] = {}
    first_boot = True
    if state_file.is_file() and not state_file.is_symlink():
        try:
            loaded = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                prev_state = loaded
                first_boot = False
        except (OSError, ValueError):
            pass

    paths = host_quota_log_paths(ctx.real_home)
    raw_offsets = prev_state.get("offsets")
    offsets: Dict[str, int] = (
        {str(k): int(v) for k, v in raw_offsets.items() if isinstance(v, (int, float))}
        if isinstance(raw_offsets, dict)
        else {}
    )

    triggered, reason, next_offsets = scan_new_log_bytes_for_quota_exhaustion(
        paths,
        offsets,
        initialize_at_eof=first_boot,
    )

    prev_ledger = prev_state.get("desktop_retry_ledger")
    desktop_retry, next_ledger = poll_desktop_hub_auto_retry(
        ctx,
        ledger=prev_ledger if isinstance(prev_ledger, dict) else {},
    )
    receipt = append_recovery_audit_receipt(root_dir, desktop_retry)
    if receipt is not None:
        desktop_retry["audit_receipt_hash"] = receipt["receipt_hash"]

    allow_5h_failover = bool(
        failover_on_5h and os.environ.get("AGY_FAILOVER_ON_5H", "1").strip().lower() not in ("0", "false", "no")
    )
    if not triggered and desktop_retry.get("host_weekly_exhausted"):
        triggered = True
        reason = "Weekly Limit exhausted on Host Desktop Hub (resets at {})".format(
            desktop_retry.get("host_weekly_reset_time") or "unknown"
        )
    elif (
        not triggered
        and allow_5h_failover
        and desktop_retry.get("host_five_hour_exhausted_only")
    ):
        triggered = True
        reason = "Five Hour Limit exhausted on Host Desktop Hub (resets at {})".format(
            desktop_retry.get("host_five_hour_reset_time") or "unknown"
        )

    overview = call_tool_fn("profile_list", {}, ctx)
    flow = overview.get("flow") or {}
    profiles = overview.get("profiles") or []
    active_owner = str(flow.get("active_owner") or "host")

    switched_to: Optional[str] = None
    switch_result: Optional[Dict[str, Any]] = None
    if triggered and active_owner == "host" and profiles:
        target_slug = str(profiles[0]["manifest"]["name"])
        switch_result = call_tool_fn(
            "profile_switch",
            {
                "name": target_slug,
                "automations_mode": "active",
                "include_sessions": True,
                "copy_prompt": copy_prompt,
                "launch": launch,
            },
            ctx,
        )
        switched_to = target_slug

    new_state = {
        "offsets": next_offsets,
        "desktop_retry_ledger": next_ledger,
        "last_desktop_auto_retry": {
            "checked_at": desktop_retry.get("checked_at"),
            "resumed_total": desktop_retry.get("resumed_total", 0),
            "stalled_total": desktop_retry.get("stalled_total", 0),
            "incident_stories": desktop_retry.get("incident_stories") or [],
            "resumed_conversations": desktop_retry.get("resumed_conversations") or [],
            "host_five_hour_exhausted_only": desktop_retry.get("host_five_hour_exhausted_only", False),
            "host_five_hour_reset_time": desktop_retry.get("host_five_hour_reset_time"),
        },
        "updated_at": utc_now_iso(),
        "last_triggered_at": utc_now_iso() if switched_to else prev_state.get("last_triggered_at"),
        "last_reason": reason if switched_to else prev_state.get("last_reason"),
        "last_switched_to": switched_to or prev_state.get("last_switched_to"),
    }
    atomic_write_json(state_file, new_state, mode=0o600)
    return {
        "checked_at": new_state["updated_at"],
        "initialized": first_boot,
        "quota_exhausted_detected": triggered,
        "reason": reason,
        "active_owner_before": active_owner,
        "switched_to": switched_to,
        "switch": switch_result,
        "desktop_auto_retry": desktop_retry,
    }
