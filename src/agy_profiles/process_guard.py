"""Verified PID matching, lock inspection/repair, detached launch, and staged shutdown."""

from __future__ import annotations

import os
from pathlib import Path
try:
    import pwd
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore[assignment]
import re
import signal
import subprocess
import sys
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

HOST_DATA_DIR_RELPATHS: Dict[str, str] = {
    "hub": "Library/Application Support/Antigravity",
    "ide": "Library/Application Support/Antigravity IDE",
}

LOCK_FILENAMES: Tuple[str, ...] = (
    "SingletonLock",
    "SingletonSocket",
    "SingletonCookie",
    "DevToolsActivePort",
)

# Bundled Antigravity Language Server localhost certificate SPKI SHA-256 pin.
# Passing --ignore-certificate-errors-spki-list=<pin> to Electron ensures Chromium
# propagates the pin to every respawned NetworkService utility process so
# https://127.0.0.1:<port> never fails with ERR_CERT_AUTHORITY_INVALID.
AGY_LS_CERT_SPKI_PIN = "JeyXQw7kf/EFhXkPlmSMOr8ABBItZp+OzlpjMuFUdas="
AGY_LS_CERT_SPKI_FLAG = "--ignore-certificate-errors-spki-list={}".format(AGY_LS_CERT_SPKI_PIN)

_PROCESS_TYPE_RE = re.compile(r"(?:^|\s)--type=")
_USER_DATA_DIR_FLAG_RE = re.compile(r"(?:^|\s)--user-data-dir(?:=|\s)")


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


def command_matches_host_target(
    command: str,
    binary_path: str,
    default_data_dir: Path,
    allow_default_no_flag: bool = True,
) -> bool:
    """Match a primary Host Antigravity root process while excluding sandbox instances."""
    if not binary_path:
        return False
    if command != binary_path and not command.startswith(binary_path + " "):
        return False
    if _PROCESS_TYPE_RE.search(command):
        return False
    if _USER_DATA_DIR_FLAG_RE.search(command):
        return command_matches_user_data_dir(command, str(default_data_dir.resolve()))
    return bool(allow_default_no_flag)


def _expand_process_tree(
    rows: List[Dict[str, Any]],
    seed_pids: Set[int],
) -> List[Dict[str, Any]]:
    """Expand seed PIDs to include all direct and indirect child processes."""
    if not seed_pids:
        return []
    matched_pids = set(seed_pids)
    changed = True
    while changed:
        changed = False
        for row in rows:
            pid = int(row["pid"])
            ppid = int(row["ppid"])
            if ppid in matched_pids and pid not in matched_pids:
                matched_pids.add(pid)
                changed = True
    return [row for row in rows if int(row["pid"]) in matched_pids]


def list_profile_processes(
    profile_dir: Path,
    ps_rows: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Identify processes owned by each target inside profile_dir using exact data-dir matching."""
    rows = ps_rows if ps_rows is not None else list_all_processes()
    out: Dict[str, List[Dict[str, Any]]] = {"hub": [], "ide": []}

    for target, subdir in DATA_SUBDIR_BY_TARGET.items():
        data_dir = str((profile_dir / subdir).resolve())
        matched_pids: Set[int] = {
            int(row["pid"])
            for row in rows
            if command_matches_user_data_dir(str(row.get("command", "")), data_dir)
        }
        out[target] = _expand_process_tree(rows, matched_pids)
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
    resolved_data_dir = str(data_dir.resolve())
    root_pids = sorted(
        int(p["pid"])
        for p in procs
        if command_matches_user_data_dir(str(p.get("command", "")), resolved_data_dir)
        and not _PROCESS_TYPE_RE.search(str(p.get("command", "")))
    )
    if not root_pids and pids:
        root_pids = [pids[0]]
    schedule_count = sum(
        1 for p in procs if "multicall schedule" in str(p.get("command", ""))
    )

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
        "root_pids": root_pids,
        "pids": pids,
        "schedule_count": schedule_count,
        "lock_files": existing_locks,
    }


def _passwd_home_dir() -> Optional[Path]:
    if pwd is None:
        return None
    try:
        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (KeyError, OSError):
        return None


def inspect_host_runtime(
    real_home: Optional[Path] = None,
    targets: Optional[Dict[str, TargetInfo]] = None,
    ps_rows: Optional[List[Dict[str, Any]]] = None,
    allow_default_no_flag: Optional[bool] = None,
) -> Dict[str, Dict[str, Any]]:
    """Inspect live runtime state and cron runners for primary Host Antigravity targets."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    pw_home = _passwd_home_dir()
    effective_allow_no_flag = (
        bool(allow_default_no_flag)
        if allow_default_no_flag is not None
        else (
            real_home is None
            or host_home == Path.home().resolve()
            or (pw_home is not None and host_home == pw_home)
        )
    )
    target_map = targets if targets is not None else detect_targets()
    rows = ps_rows if ps_rows is not None else list_all_processes()

    out: Dict[str, Dict[str, Any]] = {}
    for tgt in ("hub", "ide"):
        default_data_dir = host_home / HOST_DATA_DIR_RELPATHS[tgt]
        info = target_map.get(tgt)
        bin_path = (info.binary_path or "") if info and info.installed else ""
        initial_roots: Set[int] = set()
        if bin_path:
            for row in rows:
                if command_matches_host_target(
                    str(row.get("command", "")),
                    bin_path,
                    default_data_dir,
                    allow_default_no_flag=effective_allow_no_flag,
                ):
                    initial_roots.add(int(row["pid"]))

        matched_rows = _expand_process_tree(rows, initial_roots)
        pids = [int(r["pid"]) for r in matched_rows]
        root_pids = sorted(initial_roots)
        if not root_pids and pids:
            root_pids = [pids[0]]
        schedule_count = sum(
            1 for r in matched_rows if "multicall schedule" in str(r.get("command", ""))
        )

        existing_locks: List[str] = []
        if default_data_dir.is_dir():
            for fname in LOCK_FILENAMES:
                candidate = default_data_dir / fname
                if candidate.exists() or candidate.is_symlink():
                    existing_locks.append(fname)

        if pids:
            state = "running"
        elif existing_locks:
            state = "stale-lock"
        else:
            state = "stopped"

        out[tgt] = {
            "target": tgt,
            "state": state,
            "root_pids": root_pids,
            "pids": pids,
            "schedule_count": schedule_count,
            "lock_files": existing_locks,
        }
    return out


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

    cmd: List[str] = [
        target_info.binary_path,
        "--user-data-dir={}".format(str(data_dir)),
        AGY_LS_CERT_SPKI_FLAG,
    ]
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

    host_home = (real_home if real_home is not None else Path.home()).resolve()
    env = os.environ.copy()
    env["HOME"] = str(sandbox_home)
    env["ZDOTDIR"] = str(sandbox_home)
    env["XDG_CONFIG_HOME"] = str(sandbox_home / ".config")
    env["XDG_DATA_HOME"] = str(sandbox_home / ".local" / "share")
    env["XDG_CACHE_HOME"] = str(sandbox_home / ".cache")
    safe_bin_dirs = [
        str(host_home / ".local" / "bin"),
        str(host_home / ".cargo" / "bin"),
        str(host_home / ".bun" / "bin"),
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
    ]
    existing_path_parts = [p for p in env.get("PATH", "").split(":") if p]
    for bdir in reversed(safe_bin_dirs):
        if Path(bdir).is_dir() and bdir not in existing_path_parts:
            existing_path_parts.insert(0, bdir)
    if existing_path_parts:
        env["PATH"] = ":".join(existing_path_parts)
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


def inspect_host_hub_tls_health(
    real_home: Optional[Path] = None,
    host_hub_runtime: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Detect whether Host Antigravity Hub hit ERR_CERT_AUTHORITY_INVALID after a NetworkService restart."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    hub_rt = (
        host_hub_runtime
        if host_hub_runtime is not None
        else inspect_host_runtime(real_home=host_home).get("hub", {})
    )
    running = hub_rt.get("state") == "running"
    main_log = host_home / "Library" / "Logs" / "Antigravity" / "main.log"
    tls_broken = False
    detail = "Host Hub localhost TLS pipe healthy"

    if main_log.is_file() and not main_log.is_symlink():
        try:
            size = int(main_log.stat().st_size)
            read_from = max(0, size - 65536)
            with main_log.open("rb") as fh:
                fh.seek(read_from)
                tail_text = fh.read(size - read_from).decode("utf-8", errors="replace")
            last_start = tail_text.rfind("Starting app (")
            active_segment = tail_text[last_start:] if last_start >= 0 else tail_text
            if "ERR_CERT_AUTHORITY_INVALID" in active_segment and "Shutting down language server" not in active_segment[active_segment.rfind("ERR_CERT_AUTHORITY_INVALID"):]:
                tls_broken = True
                detail = (
                    "Host Hub logged ERR_CERT_AUTHORITY_INVALID after NetworkService restart; "
                    "run 'agy-profiles repair host' to restore Language Server TLS trust"
                )
        except OSError:
            pass

    return {
        "running": running,
        "tls_broken": tls_broken,
        "detail": detail,
    }


def repair_host_hub(
    real_home: Optional[Path] = None,
    launch: bool = True,
    timeout_sec: float = 5.0,
    targets_override: Optional[Dict[str, TargetInfo]] = None,
) -> Dict[str, Any]:
    """Stop broken Host Antigravity Hub PIDs, clear stale Host locks, and relaunch with open -n."""
    host_home = (real_home if real_home is not None else Path.home()).resolve()
    targets = targets_override if targets_override is not None else detect_targets()
    hub_info = targets.get("hub")

    rt_before = inspect_host_runtime(real_home=host_home, targets=targets)
    hub_pids = list(rt_before.get("hub", {}).get("pids") or [])
    signaled_pids: List[int] = []
    forced_pids: List[int] = []

    # Signal children before the root Electron PID so language_server exits cleanly.
    for pid in reversed(hub_pids):
        try:
            os.kill(pid, signal.SIGTERM)
            signaled_pids.append(pid)
        except ProcessLookupError:
            pass

    deadline = time.monotonic() + max(0.2, float(timeout_sec))
    remaining = list(hub_pids)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.2)
        fresh_pids = set(inspect_host_runtime(real_home=host_home, targets=targets).get("hub", {}).get("pids") or [])
        remaining = [pid for pid in remaining if pid in fresh_pids and _pid_is_alive(pid)]

    if remaining:
        fresh_pids = set(inspect_host_runtime(real_home=host_home, targets=targets).get("hub", {}).get("pids") or [])
        for pid in remaining:
            if pid in fresh_pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                    forced_pids.append(pid)
                except ProcessLookupError:
                    pass
        time.sleep(0.2)

    host_data_dir = host_home / HOST_DATA_DIR_RELPATHS["hub"]
    removed_locks: List[str] = []
    if host_data_dir.is_dir() and not host_data_dir.is_symlink():
        for fname in LOCK_FILENAMES:
            lock_slot = host_data_dir / fname
            if lock_slot.exists() or lock_slot.is_symlink():
                try:
                    lock_slot.unlink()
                    removed_locks.append(fname)
                except OSError:
                    pass

    launched = False
    if launch:
        if hub_info is None or not hub_info.installed or not hub_info.app_path:
            raise ToolError(
                "target_not_found",
                "Host Antigravity.app is not installed in /Applications.",
                "Install Antigravity.app in /Applications and retry.",
            )
        clean_env: Dict[str, str] = {
            "HOME": str(host_home),
            "USER": os.environ.get("USER") or host_home.name,
            "LOGNAME": os.environ.get("LOGNAME") or host_home.name,
            "SHELL": os.environ.get("SHELL") or "/bin/zsh",
            "TMPDIR": os.environ.get("TMPDIR") or "/tmp",
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        }
        if sys.platform == "darwin" and Path("/usr/bin/open").exists():
            proc = subprocess.run(
                [
                    "/usr/bin/open",
                    "-n",
                    "-a",
                    hub_info.app_path,
                    "--args",
                    AGY_LS_CERT_SPKI_FLAG,
                ],
                env=clean_env,
                cwd=str(host_home),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode != 0:
                raise ToolError(
                    "process_error",
                    "Failed to relaunch Host Antigravity.app: {}.".format((proc.stderr or proc.stdout).strip()),
                    "Open /Applications/Antigravity.app manually or inspect macOS LaunchServices.",
                )
            launched = True
        elif hub_info.binary_path:
            subprocess.Popen(
                [hub_info.binary_path, AGY_LS_CERT_SPKI_FLAG],
                env=clean_env,
                cwd=str(host_home),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            launched = True

    return {
        "profile": "host",
        "locks_removed": {"hub": removed_locks, "ide": []},
        "signaled_pids": signaled_pids,
        "forced_pids": forced_pids,
        "relaunched": launched,
    }


GPU_SHADER_CACHE_DIRS: Tuple[str, ...] = (
    "GPUCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GraphiteDawnCache",
)


def _purge_gpu_shader_caches(data_dir: Path) -> List[str]:
    """Delete only Metal/WebGPU shader caches inside data_dir while keeping sessions, DBs, and OAuth intact."""
    cleared: List[str] = []
    if not data_dir.is_dir():
        return cleared
    candidates: List[Path] = []
    for cache_name in GPU_SHADER_CACHE_DIRS:
        candidates.append(data_dir / cache_name)
        candidates.append(data_dir / "Default" / cache_name)
    for cdir in candidates:
        if not cdir.is_dir() or cdir.is_symlink():
            continue
        removed_any = False
        try:
            for child in cdir.iterdir():
                if child.is_symlink() or child.is_file():
                    child.unlink()
                    removed_any = True
        except OSError:
            pass
        if removed_any:
            cleared.append(str(cdir))
    return cleared


def heal_electron_compositor(
    scope: str = "all",
    target: str = "all",
    deep: bool = False,
    root: Optional[Path] = None,
    real_home: Optional[Path] = None,
    ps_rows: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Recover black Antigravity windows without Cmd+Q by purging GPU shader caches and recycling --type=gpu-process."""
    if target == "all":
        targets: Tuple[str, ...] = ("hub", "ide")
    else:
        targets = (validate_target(target),)

    base_home = (real_home if real_home is not None else Path.home()).expanduser()
    detected = detect_targets()
    rows = ps_rows if ps_rows is not None else list_all_processes()

    data_dirs_to_heal: List[Tuple[str, str, Path]] = []
    if scope in ("host", "all"):
        for tgt in targets:
            data_dirs_to_heal.append(("host", tgt, base_home / HOST_DATA_DIR_RELPATHS[tgt]))

    if scope != "host" and root is not None and root.is_dir():
        if scope == "all":
            for child in sorted(root.iterdir()):
                if child.is_dir() and not child.name.startswith(".") and (child / "profile.json").is_file():
                    for tgt in targets:
                        data_dirs_to_heal.append((child.name, tgt, child / DATA_SUBDIR_BY_TARGET[tgt]))
        else:
            prof_dir = ensure_within_root(root, root / scope)
            for tgt in targets:
                data_dirs_to_heal.append((scope, tgt, prof_dir / DATA_SUBDIR_BY_TARGET[tgt]))

    cleared_caches: List[str] = []
    recycled_gpu_pids: List[int] = []
    recycled_renderer_pids: List[int] = []
    preserved_roots: List[int] = []

    for owner_name, tgt, data_dir in data_dirs_to_heal:
        cleared_caches.extend(_purge_gpu_shader_caches(data_dir))
        resolved_dir = str(data_dir.resolve()) if data_dir.exists() else str(data_dir)
        tinfo: Optional[TargetInfo] = detected.get(tgt)
        bin_path = tinfo.binary_path if (tinfo and tinfo.installed) else ""

        seed_pids: Set[int] = set()
        for row in rows:
            cmd = str(row.get("command", ""))
            pid = int(row["pid"])
            if owner_name == "host":
                if command_matches_host_target(cmd, bin_path, data_dir) or command_matches_user_data_dir(cmd, resolved_dir):
                    seed_pids.add(pid)
            else:
                if command_matches_user_data_dir(cmd, resolved_dir):
                    seed_pids.add(pid)

        tree = _expand_process_tree(rows, seed_pids)
        for row in tree:
            pid = int(row["pid"])
            cmd = str(row.get("command", ""))
            if not _PROCESS_TYPE_RE.search(cmd):
                if "language_server" not in cmd and pid not in preserved_roots:
                    preserved_roots.append(pid)
                continue
            if "--type=gpu-process" in cmd and pid not in recycled_gpu_pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                    recycled_gpu_pids.append(pid)
                except ProcessLookupError:
                    pass
            elif deep and "--type=renderer" in cmd and pid not in recycled_renderer_pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                    recycled_renderer_pids.append(pid)
                except ProcessLookupError:
                    pass

    if recycled_gpu_pids or recycled_renderer_pids:
        time.sleep(0.35)

    host_hub_repaired = False
    if ps_rows is None and scope in ("host", "all") and "hub" in targets:
        tls_check = inspect_host_hub_tls_health(real_home=base_home)
        if tls_check.get("tls_broken"):
            repair_host_hub(real_home=base_home, launch=True)
            host_hub_repaired = True

    return {
        "scope": scope,
        "target": target,
        "deep": bool(deep),
        "recycled_gpu_pids": recycled_gpu_pids,
        "recycled_renderer_pids": recycled_renderer_pids,
        "preserved_root_pids": preserved_roots,
        "cleared_shader_caches": cleared_caches,
        "host_hub_repaired": host_hub_repaired,
        "healed_at": utc_now_iso(),
    }
