"""Verified PID matching, lock inspection/repair, detached launch, and staged shutdown."""

from __future__ import annotations

import os
from pathlib import Path
import re
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from agy_profiles.config import (
    ProfileManifest,
    TargetInfo,
    atomic_write_json,
    detect_targets,
    ensure_within_root,
    save_manifest,
    validate_target,
)
from agy_profiles.errors import ToolError
from agy_profiles.evidence import utc_now_iso
from agy_profiles.isolation import provision_profile_dirs, purge_stale_caches_if_upgraded

DATA_SUBDIR_BY_TARGET: Dict[str, str] = {
    "hub": "data",
    "ide": "ide-data",
}

LOCK_FILENAMES: Tuple[str, ...] = (
    "SingletonLock",
    "SingletonSocket",
    "SingletonCookie",
    "DevToolsActivePort",
)


def list_all_processes() -> List[Dict[str, Any]]:
    """Read host process table with closed stdin and bounded wall timeout."""
    proc = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid=,pgid=,command="],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=5,
        check=False,
    )
    if proc.returncode != 0:
        return []
    rows: List[Dict[str, Any]] = []
    for raw_line in proc.stdout.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 3)
        if len(parts) < 4:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            pgid = int(parts[2])
        except ValueError:
            continue
        rows.append({"pid": pid, "ppid": ppid, "pgid": pgid, "command": parts[3]})
    return rows


def command_matches_user_data_dir(command: str, resolved_data_dir: str) -> bool:
    """Strictly verify --user-data-dir=<exact_path> token boundary in command line."""
    if not resolved_data_dir:
        return False
    pattern = r"(?:^|\s)--user-data-dir=" + re.escape(resolved_data_dir) + r"(?:\s|$)"
    return bool(re.search(pattern, command))


def list_profile_processes(
    profile_dir: Path,
    ps_rows: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Identify processes owned by each target inside profile_dir using exact data-dir matching."""
    rows = ps_rows if ps_rows is not None else list_all_processes()
    out: Dict[str, List[Dict[str, Any]]] = {"hub": [], "ide": []}

    for target, subdir in DATA_SUBDIR_BY_TARGET.items():
        data_dir = str((profile_dir / subdir).resolve())
        matched_pids: Set[int] = set()
        for row in rows:
            if command_matches_user_data_dir(str(row.get("command", "")), data_dir):
                matched_pids.add(int(row["pid"]))

        # Include direct and indirect child processes (such as language_server and helpers).
        if matched_pids:
            changed = True
            while changed:
                changed = False
                for row in rows:
                    pid = int(row["pid"])
                    ppid = int(row["ppid"])
                    if ppid in matched_pids and pid not in matched_pids:
                        matched_pids.add(pid)
                        changed = True

        out[target] = [row for row in rows if int(row["pid"]) in matched_pids]
    return out


def inspect_locks(
    profile_dir: Path,
    target: str,
    ps_rows: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Classify runtime state for a profile target as running, stale-lock, or stopped."""
    valid_target = validate_target(target)
    procs = list_profile_processes(profile_dir, ps_rows=ps_rows)[valid_target]
    pids = [int(p["pid"]) for p in procs]

    data_dir = profile_dir / DATA_SUBDIR_BY_TARGET[valid_target]
    existing_locks: List[str] = []
    for fname in LOCK_FILENAMES:
        candidate = data_dir / fname
        if candidate.exists() or candidate.is_symlink():
            existing_locks.append(fname)

    run_state_file = profile_dir / "run.{}.json".format(valid_target)
    if run_state_file.exists() or run_state_file.is_symlink():
        existing_locks.append(run_state_file.name)

    if pids:
        state = "running"
    elif existing_locks:
        state = "stale-lock"
    else:
        state = "stopped"

    return {
        "target": valid_target,
        "state": state,
        "pids": pids,
        "lock_files": existing_locks,
    }


def _unlink_lock_path(base: Path, target_path: Path) -> None:
    if target_path.is_symlink():
        # Remove symlink slot itself if its parent sits inside base.
        parent_resolved = target_path.parent.resolve()
        parent_resolved.relative_to(base.resolve())
        target_path.unlink()
    elif target_path.exists():
        verified = ensure_within_root(base, target_path)
        if verified.is_dir():
            return
        verified.unlink()


def repair_locks(
    root: Path,
    profile_dir: Path,
    target: Optional[str] = None,
    allow_live_noop: bool = False,
) -> Dict[str, Any]:
    """Remove stale Chromium locks and run markers inside verified profile directory."""
    verified_profile = ensure_within_root(root, profile_dir)
    targets_to_clean = (validate_target(target),) if target is not None else ("hub", "ide")
    ps_rows = list_all_processes()
    removed: Dict[str, List[str]] = {"hub": [], "ide": []}

    for tgt in targets_to_clean:
        status = inspect_locks(verified_profile, tgt, ps_rows=ps_rows)
        if status["state"] == "running":
            if allow_live_noop:
                continue
            raise ToolError(
                "profile_running",
                "Cannot repair locks while target {!r} is running (PIDs: {}).".format(tgt, status["pids"]),
                "Stop the running profile first with 'agy-profiles stop'.",
                {"target": tgt, "pids": status["pids"]},
            )
        data_dir = ensure_within_root(verified_profile, verified_profile / DATA_SUBDIR_BY_TARGET[tgt])
        for fname in LOCK_FILENAMES:
            lock_path = data_dir / fname
            if lock_path.exists() or lock_path.is_symlink():
                _unlink_lock_path(verified_profile, lock_path)
                removed[tgt].append("{}/{}".format(DATA_SUBDIR_BY_TARGET[tgt], fname))
        run_file = verified_profile / "run.{}.json".format(tgt)
        if run_file.exists() or run_file.is_symlink():
            _unlink_lock_path(verified_profile, run_file)
            removed[tgt].append(run_file.name)

    return {"removed": removed}


def launch_profile(
    root: Path,
    profile_dir: Path,
    manifest: ProfileManifest,
    target: Optional[str] = None,
    workspace: Optional[str] = None,
    real_home: Optional[Path] = None,
    targets_override: Optional[Dict[str, TargetInfo]] = None,
) -> Dict[str, Any]:
    """Provision sandbox isolation, clean stale locks, and launch target app cleanly."""
    chosen_target = validate_target(target or manifest.default_target)
    targets = targets_override if targets_override is not None else detect_targets()
    target_info = targets.get(chosen_target)
    if target_info is None or not target_info.installed or not target_info.binary_path:
        raise ToolError(
            "target_not_found",
            "Target {!r} is not installed on this machine.".format(chosen_target),
            "Install Antigravity.app or Antigravity IDE.app in /Applications and retry.",
            {"target": chosen_target},
        )

    verified_profile = ensure_within_root(root, profile_dir)
    current = inspect_locks(verified_profile, chosen_target)
    if current["state"] == "running":
        return {
            "profile": manifest.name,
            "target": chosen_target,
            "already_running": True,
            "pids": current["pids"],
            "purged_caches": [],
        }
    if current["state"] == "stale-lock":
        repair_locks(root, verified_profile, target=chosen_target)

    provision_info = provision_profile_dirs(root, manifest, real_home=real_home)
    purged_caches = purge_stale_caches_if_upgraded(verified_profile, manifest, targets)
    manifest.last_launched_at = utc_now_iso()
    save_manifest(root, verified_profile, manifest)

    sandbox_home = ensure_within_root(verified_profile, verified_profile / "home")
    data_dir = ensure_within_root(verified_profile, verified_profile / DATA_SUBDIR_BY_TARGET[chosen_target])

    cmd: List[str] = [target_info.binary_path, "--user-data-dir={}".format(str(data_dir))]
    if chosen_target == "ide":
        ext_dir = ensure_within_root(sandbox_home, sandbox_home / ".antigravity-ide" / "extensions")
        ext_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(ext_dir), 0o700)
        cmd.append("--extensions-dir={}".format(str(ext_dir)))

    cwd_path = str(sandbox_home)
    if workspace:
        ws_resolved = Path(workspace).expanduser().resolve()
        if not ws_resolved.exists():
            raise ToolError(
                "invalid_argument",
                "Workspace path {!r} does not exist.".format(workspace),
                "Provide an existing workspace folder or file path.",
                {"workspace": workspace},
            )
        cmd.append(str(ws_resolved))
        cwd_path = str(ws_resolved if ws_resolved.is_dir() else ws_resolved.parent)

    env = os.environ.copy()
    env["HOME"] = str(sandbox_home)
    env["ZDOTDIR"] = str(sandbox_home)
    env["XDG_CONFIG_HOME"] = str(sandbox_home / ".config")
    env["XDG_DATA_HOME"] = str(sandbox_home / ".local" / "share")
    env["XDG_CACHE_HOME"] = str(sandbox_home / ".cache")
    if manifest.auth_mode == "isolated-file":
        env["SSH_CONNECTION"] = "local"
    else:
        env.pop("SSH_CONNECTION", None)

    log_path = ensure_within_root(verified_profile, verified_profile / "logs" / "{}.log".format(chosen_target))
    log_fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            cwd=cwd_path,
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        raise ToolError(
            "process_error",
            "Failed to launch {} binary: {}.".format(chosen_target, exc),
            "Verify execute permissions on {}.".format(target_info.binary_path),
        ) from exc
    finally:
        os.close(log_fd)

    run_file = ensure_within_root(verified_profile, verified_profile / "run.{}.json".format(chosen_target))
    atomic_write_json(
        run_file,
        {
            "pid": proc.pid,
            "target": chosen_target,
            "started_at": utc_now_iso(),
            "data_dir": str(data_dir),
            "version": target_info.version,
        },
        mode=0o600,
    )

    return {
        "profile": manifest.name,
        "target": chosen_target,
        "already_running": False,
        "pid": proc.pid,
        "data_dir": str(data_dir),
        "sandbox_home": provision_info["sandbox_home"],
        "auth_mode": manifest.auth_mode,
        "purged_caches": purged_caches,
        "log_file": str(log_path),
    }


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop_profile(
    root: Path,
    profile_dir: Path,
    target: str = "all",
    timeout_sec: float = 5.0,
) -> Dict[str, Any]:
    """Terminate verified profile PIDs gracefully with SIGTERM, then SIGKILL fallback."""
    verified_profile = ensure_within_root(root, profile_dir)
    if target == "all":
        targets: Tuple[str, ...] = ("hub", "ide")
    else:
        targets = (validate_target(target),)

    ps_rows = list_all_processes()
    proc_map = list_profile_processes(verified_profile, ps_rows=ps_rows)
    signaled_pids: List[int] = []
    forced_pids: List[int] = []

    target_pids: List[int] = []
    for tgt in targets:
        for row in proc_map.get(tgt, []):
            pid = int(row["pid"])
            if pid not in target_pids:
                target_pids.append(pid)

    for pid in target_pids:
        try:
            os.kill(pid, signal.SIGTERM)
            signaled_pids.append(pid)
        except ProcessLookupError:
            pass

    deadline = time.monotonic() + max(0.2, float(timeout_sec))
    remaining = list(target_pids)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.15)
        fresh_map = list_profile_processes(verified_profile)
        live_verified = {
            int(row["pid"])
            for tgt in targets
            for row in fresh_map.get(tgt, [])
        }
        remaining = [pid for pid in remaining if pid in live_verified and _pid_is_alive(pid)]

    if remaining:
        fresh_map = list_profile_processes(verified_profile)
        live_verified = {
            int(row["pid"])
            for tgt in targets
            for row in fresh_map.get(tgt, [])
        }
        for pid in remaining:
            if pid in live_verified:
                try:
                    os.kill(pid, signal.SIGKILL)
                    forced_pids.append(pid)
                except ProcessLookupError:
                    pass
        time.sleep(0.2)

    for tgt in targets:
        repair_locks(root, verified_profile, target=tgt, allow_live_noop=True)

    return {
        "stopped": targets,
        "signaled_pids": signaled_pids,
        "forced_pids": forced_pids,
    }
