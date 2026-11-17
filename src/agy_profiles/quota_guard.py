"""Read-only Host quota-exhaustion detector and automatic backup failover watchdog."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from agy_profiles.config import atomic_write_json, ensure_within_root
from agy_profiles.evidence import utc_now_iso

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
    r"(?:runner\.go:|Monitor\s+sir_|severe_internal_risks)",
    re.IGNORECASE,
)


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
) -> Dict[str, Any]:
    """Check Host logs once and automatically switch quota onto the standby backup profile if exhausted."""
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
    }
