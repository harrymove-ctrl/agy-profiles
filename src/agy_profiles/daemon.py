"""Persistent macOS launchd services for 24/7 quota watchdog, caffeinate anti-sleep, and Web Console."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import plistlib
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Dict, IO, List, Optional
import webbrowser

from agy_profiles.config import atomic_write_json
from agy_profiles.errors import ToolError
from agy_profiles.evidence import utc_now_iso
from agy_profiles.tools import RuntimeContext
from agy_profiles.web_server import (
    format_host_header,
    load_or_create_web_secrets,
    validate_bind_host,
)

WATCHDOG_LABEL = "dev.agy-profiles.watchdog"
WEB_LABEL = "dev.agy-profiles.web"
WATCHDOG_LOCK_FILENAME = ".watchdog.lock"


def validate_port_number(port: int) -> int:
    """Validate non-ephemeral TCP port range 1 to 65535 for persistent launchd services."""
    try:
        val = int(port)
    except (TypeError, ValueError) as exc:
        raise ToolError("invalid_argument", "Port must be an integer.", http_status=400) from exc
    if val < 1 or val > 65535:
        raise ToolError(
            "invalid_argument",
            "Persistent daemon port must be between 1 and 65535 (got {}).".format(val),
            http_status=400,
        )
    return val


def acquire_watchdog_lock(root: Path) -> Optional[IO[str]]:
    """Acquire non-blocking exclusive flock on <root>/.watchdog.lock so only one watchdog runs."""
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(str(root), 0o700)
    lock_path = root / WATCHDOG_LOCK_FILENAME
    fh = open(lock_path, "a+", encoding="utf-8")
    try:
        os.chmod(str(lock_path), 0o600)
    except OSError:
        pass
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    fh.seek(0)
    fh.truncate()
    fh.write("{}\n".format(os.getpid()))
    fh.flush()
    return fh


def is_watchdog_locked(root: Path) -> Dict[str, Any]:
    """Inspect whether an active watchdog process currently holds .watchdog.lock."""
    lock_path = root / WATCHDOG_LOCK_FILENAME
    if not lock_path.is_file():
        return {"locked": False, "pid": None}
    pid_val: Optional[int] = None
    try:
        raw = lock_path.read_text(encoding="utf-8").strip()
        if raw:
            pid_val = int(raw.splitlines()[0].strip())
    except (OSError, ValueError):
        pid_val = None
    probe = acquire_watchdog_lock(root)
    if probe is not None:
        try:
            fcntl.flock(probe.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        probe.close()
        return {"locked": False, "pid": None}
    return {"locked": True, "pid": pid_val}


def _resolve_python_executable() -> str:
    for candidate in (
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        sys.executable,
        shutil.which("python3") or "",
        "/usr/bin/python3",
    ):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return sys.executable


def _resolve_agyp_entrypoint(ctx: RuntimeContext) -> Path:
    if ctx.cli_bin_path and Path(ctx.cli_bin_path).is_file():
        return Path(ctx.cli_bin_path).resolve()
    repo_bin = Path(__file__).resolve().parents[2] / "bin" / "agyp"
    if repo_bin.is_file():
        return repo_bin
    home_dir = ctx.real_home or Path.home()
    local_bin = home_dir / ".local" / "bin" / "agyp"
    return local_bin


def _launch_agents_dir(ctx: RuntimeContext) -> Path:
    base_home = ctx.real_home or Path.home()
    return base_home / "Library" / "LaunchAgents"


def _logs_dir(ctx: RuntimeContext) -> Path:
    base_home = ctx.real_home or Path.home()
    return base_home / "Library" / "Logs" / "agy-profiles"


def _daemon_env(ctx: RuntimeContext) -> Dict[str, str]:
    home_dir = str(ctx.real_home or Path.home())
    path_parts = [
        "{}/.local/bin".format(home_dir),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ]
    return {
        "HOME": home_dir,
        "PATH": ":".join(path_parts),
        "AGY_PROFILES_DIR": str(ctx.root),
        "PYTHONUNBUFFERED": "1",
    }


def build_watchdog_plist_dict(
    ctx: RuntimeContext,
    interval_sec: float = 5.0,
    prevent_sleep: bool = True,
) -> Dict[str, Any]:
    """Construct launchd plist dictionary for the 24/7 quota failover watchdog."""
    py_exe = _resolve_python_executable()
    agyp_bin = str(_resolve_agyp_entrypoint(ctx))
    logs_dir = _logs_dir(ctx)
    cmd: List[str] = []
    if prevent_sleep and os.path.isfile("/usr/bin/caffeinate"):
        cmd.extend(["/usr/bin/caffeinate", "-i"])
    cmd.extend([py_exe, agyp_bin, "watchdog", "--interval", "{:.1f}".format(max(1.0, float(interval_sec)))])
    return {
        "Label": WATCHDOG_LABEL,
        "ProgramArguments": cmd,
        "EnvironmentVariables": _daemon_env(ctx),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 5,
        "WorkingDirectory": str(ctx.real_home or Path.home()),
        "StandardOutPath": str(logs_dir / "watchdog.log"),
        "StandardErrorPath": str(logs_dir / "watchdog.log"),
    }


def build_web_plist_dict(
    ctx: RuntimeContext,
    host: str = "127.0.0.1",
    port: int = 47920,
) -> Dict[str, Any]:
    """Construct launchd plist dictionary for the persistent loopback Web Console."""
    clean_host = validate_bind_host(host)
    clean_port = validate_port_number(port)
    py_exe = _resolve_python_executable()
    agyp_bin = str(_resolve_agyp_entrypoint(ctx))
    logs_dir = _logs_dir(ctx)
    cmd = [
        py_exe,
        agyp_bin,
        "web",
        "--host",
        clean_host,
        "--port",
        str(clean_port),
        "--no-open",
    ]
    return {
        "Label": WEB_LABEL,
        "ProgramArguments": cmd,
        "EnvironmentVariables": _daemon_env(ctx),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 5,
        "WorkingDirectory": str(ctx.real_home or Path.home()),
        "StandardOutPath": str(logs_dir / "web.log"),
        "StandardErrorPath": str(logs_dir / "web.log"),
    }


def _is_tcp_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _stop_stray_daemons(port: int) -> List[int]:
    """Terminate lingering watchdog or standalone web processes after bootout so launchd binds cleanly."""
    stopped_pids: List[int] = []
    my_pid = os.getpid()
    try:
        proc = subprocess.run(
            ["/bin/ps", "-axo", "pid=,command="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return stopped_pids

    port_flag = "--port {}".format(port)
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid == my_pid:
            continue
        cmdline = parts[1]
        if "--sidecar" in cmdline or " mcp" in cmdline or " daemon" in cmdline:
            continue
        is_agyp = ("agyp" in cmdline) or ("agy-profiles" in cmdline) or ("agy_profiles" in cmdline)
        if not is_agyp:
            continue
        is_wd = " watchdog" in cmdline
        is_web = (" web" in cmdline) and (port_flag in cmdline or "--port=" + str(port) in cmdline)
        if is_wd or is_web:
            try:
                os.kill(pid, signal.SIGTERM)
                stopped_pids.append(pid)
            except OSError:
                pass
    if stopped_pids:
        time.sleep(0.4)
    return stopped_pids


def _launchctl_domain() -> str:
    return "gui/{}".format(os.getuid())


def _launchctl_reload(plist_path: Path, label: str) -> Dict[str, Any]:
    domain = _launchctl_domain()
    subprocess.run(
        ["/bin/launchctl", "bootout", domain, str(plist_path)],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    boot = subprocess.run(
        ["/bin/launchctl", "bootstrap", domain, str(plist_path)],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    kick = subprocess.run(
        ["/bin/launchctl", "kickstart", "-k", "{}/{}".format(domain, label)],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    return {
        "label": label,
        "plist_path": str(plist_path),
        "bootstrap_rc": boot.returncode,
        "kickstart_rc": kick.returncode,
        "stderr": (boot.stderr or kick.stderr or "").strip(),
    }


def _launchctl_service_info(label: str) -> Dict[str, Any]:
    domain = _launchctl_domain()
    try:
        proc = subprocess.run(
            ["/bin/launchctl", "print", "{}/{}".format(domain, label)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {"loaded": False, "pid": None, "state": "unavailable"}
    if proc.returncode != 0:
        return {"loaded": False, "pid": None, "state": "unloaded"}
    pid_val: Optional[int] = None
    state_val = "loaded"
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("pid = "):
            try:
                pid_val = int(line.split("=", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("state = "):
            state_val = line.split("=", 1)[1].strip()
    return {"loaded": True, "pid": pid_val, "state": state_val}


def _caffeinate_active() -> bool:
    try:
        proc = subprocess.run(
            ["/bin/ps", "-axo", "command="],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        for line in proc.stdout.splitlines():
            if "/usr/bin/caffeinate" in line and ("agyp" in line or "agy-profiles" in line):
                return True
    except (OSError, subprocess.SubprocessError):
        pass
    return False


def get_owner_console_url(ctx: RuntimeContext, host: str = "127.0.0.1", port: int = 47920) -> str:
    """Return persistent owner tokenized URL backed by 0o600 .web-secrets.json."""
    clean_host = validate_bind_host(host)
    clean_port = validate_port_number(port)
    _, _, owner_token = load_or_create_web_secrets(ctx.root)
    origin = "http://{}".format(format_host_header(clean_host, clean_port))
    return "{}/?token={}".format(origin, owner_token)


def install_daemons(
    ctx: RuntimeContext,
    host: str = "127.0.0.1",
    port: int = 47920,
    interval_sec: float = 5.0,
    prevent_sleep: bool = True,
    open_browser: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Write launchd LaunchAgents, activate 24/7 watchdog + web console, and optionally open browser."""
    clean_host = validate_bind_host(host)
    clean_port = validate_port_number(port)
    agents_dir = _launch_agents_dir(ctx)
    logs_dir = _logs_dir(ctx)
    ctx.root.mkdir(parents=True, exist_ok=True)
    os.chmod(str(ctx.root), 0o700)
    logs_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(logs_dir), 0o700)
    agents_dir.mkdir(parents=True, exist_ok=True)

    # Pre-initialize persistent web secrets before starting the web service so owner_token matches on boot.
    owner_url = get_owner_console_url(ctx, host=clean_host, port=clean_port)
    wd_plist = build_watchdog_plist_dict(ctx, interval_sec=interval_sec, prevent_sleep=prevent_sleep)
    web_plist = build_web_plist_dict(ctx, host=clean_host, port=clean_port)

    wd_plist_path = agents_dir / "{}.plist".format(WATCHDOG_LABEL)
    web_plist_path = agents_dir / "{}.plist".format(WEB_LABEL)
    wd_plist_path.write_bytes(plistlib.dumps(wd_plist))
    web_plist_path.write_bytes(plistlib.dumps(web_plist))
    os.chmod(str(wd_plist_path), 0o644)
    os.chmod(str(web_plist_path), 0o644)

    stopped_strays: List[int] = []
    launchctl_results: List[Dict[str, Any]] = []
    web_listening = False

    if not dry_run and sys.platform == "darwin":
        domain = _launchctl_domain()
        for p_path in (wd_plist_path, web_plist_path):
            subprocess.run(
                ["/bin/launchctl", "bootout", domain, str(p_path)],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        stopped_strays = _stop_stray_daemons(clean_port)
        launchctl_results.append(_launchctl_reload(wd_plist_path, WATCHDOG_LABEL))
        launchctl_results.append(_launchctl_reload(web_plist_path, WEB_LABEL))
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if _is_tcp_listening(clean_host, clean_port):
                web_listening = True
                break
            time.sleep(0.15)
        atomic_write_json(
            ctx.root / ".web-session.json",
            {
                "origin": "http://{}".format(format_host_header(clean_host, clean_port)),
                "owner_url": owner_url,
                "managed_by": "launchd",
                "updated_at": utc_now_iso(),
            },
            mode=0o600,
        )
        if open_browser and web_listening:
            webbrowser.open(owner_url)

    return {
        "installed": True,
        "dry_run": bool(dry_run),
        "watchdog_plist": str(wd_plist_path),
        "web_plist": str(web_plist_path),
        "prevent_idle_sleep": bool(prevent_sleep),
        "stopped_stray_pids": stopped_strays,
        "launchctl": launchctl_results,
        "web_listening": web_listening,
        "origin": "http://{}".format(format_host_header(clean_host, clean_port)),
        "owner_url": owner_url,
        "logs_dir": str(logs_dir),
    }


def daemon_status(
    ctx: RuntimeContext,
    host: str = "127.0.0.1",
    port: int = 47920,
) -> Dict[str, Any]:
    """Return live health of launchd watchdog, caffeinate assertion, and loopback Web Console."""
    clean_host = validate_bind_host(host)
    clean_port = validate_port_number(port)
    agents_dir = _launch_agents_dir(ctx)
    wd_plist_path = agents_dir / "{}.plist".format(WATCHDOG_LABEL)
    web_plist_path = agents_dir / "{}.plist".format(WEB_LABEL)
    wd_info = _launchctl_service_info(WATCHDOG_LABEL) if sys.platform == "darwin" else {"loaded": False, "pid": None, "state": "unsupported"}
    web_info = _launchctl_service_info(WEB_LABEL) if sys.platform == "darwin" else {"loaded": False, "pid": None, "state": "unsupported"}
    wd_lock = is_watchdog_locked(ctx.root)
    listening = _is_tcp_listening(clean_host, clean_port)
    owner_url = get_owner_console_url(ctx, host=clean_host, port=clean_port)
    return {
        "watchdog": {
            "label": WATCHDOG_LABEL,
            "plist_exists": wd_plist_path.is_file(),
            "plist_path": str(wd_plist_path),
            "launchd": wd_info,
            "lock": wd_lock,
            "caffeinate_idle_guard": _caffeinate_active(),
        },
        "web": {
            "label": WEB_LABEL,
            "plist_exists": web_plist_path.is_file(),
            "plist_path": str(web_plist_path),
            "launchd": web_info,
            "listening": listening,
            "origin": "http://{}".format(format_host_header(clean_host, clean_port)),
            "owner_url": owner_url,
        },
        "logs_dir": str(_logs_dir(ctx)),
    }


def open_daemon_console(
    ctx: RuntimeContext,
    host: str = "127.0.0.1",
    port: int = 47920,
    open_browser: bool = True,
) -> Dict[str, Any]:
    """Ensure the persistent Web Console is listening and open the 365-day owner session URL."""
    clean_host = validate_bind_host(host)
    clean_port = validate_port_number(port)
    auto_installed = False
    if not _is_tcp_listening(clean_host, clean_port) and sys.platform == "darwin":
        install_daemons(ctx, host=clean_host, port=clean_port, open_browser=False)
        auto_installed = True
    listening = _is_tcp_listening(clean_host, clean_port)
    owner_url = get_owner_console_url(ctx, host=clean_host, port=clean_port)
    if open_browser:
        webbrowser.open(owner_url)
    return {
        "opened": bool(open_browser),
        "auto_installed": auto_installed,
        "listening": listening,
        "origin": "http://{}".format(format_host_header(clean_host, clean_port)),
        "owner_url": owner_url,
    }


def uninstall_daemons(ctx: RuntimeContext, dry_run: bool = False) -> Dict[str, Any]:
    """Unload and remove launchd LaunchAgent plists for watchdog and web console."""
    agents_dir = _launch_agents_dir(ctx)
    removed: List[str] = []
    domain = _launchctl_domain()
    for label in (WATCHDOG_LABEL, WEB_LABEL):
        plist_path = agents_dir / "{}.plist".format(label)
        if not dry_run and sys.platform == "darwin" and plist_path.is_file():
            subprocess.run(
                ["/bin/launchctl", "bootout", domain, str(plist_path)],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        if plist_path.is_file():
            if not dry_run:
                plist_path.unlink()
            removed.append(str(plist_path))
    stopped_strays = _stop_stray_daemons(47920) if (not dry_run and sys.platform == "darwin") else []
    return {
        "uninstalled": True,
        "dry_run": bool(dry_run),
        "removed_plists": removed,
        "stopped_stray_pids": stopped_strays,
    }
