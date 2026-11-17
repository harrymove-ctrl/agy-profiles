"""Command-line interface entrypoint for agy-profiles and agyp."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import webbrowser
from typing import Any, Dict, List, Optional, Tuple

from agy_profiles import __version__
from agy_profiles.config import (
    atomic_write_json,
    ensure_within_root,
    load_manifest,
    resolve_profiles_root,
    validate_profile_name,
)
from agy_profiles.daemon import (
    _is_tcp_listening,
    acquire_watchdog_lock,
    daemon_status,
    get_owner_console_url,
    install_daemons,
    open_daemon_console,
    uninstall_daemons,
)
from agy_profiles.errors import ToolError
from agy_profiles.evidence import utc_now_iso
from agy_profiles.isolation import provision_profile_dirs
from agy_profiles.mcp_server import serve_mcp_stdio
from agy_profiles.quota_guard import (
    host_quota_log_paths,
    poll_auto_failover_once,
    scan_new_log_bytes_for_quota_exhaustion,
    snapshot_log_offsets,
)
from agy_profiles.tools import RuntimeContext, _inspect_git_dirty, call_tool
from agy_profiles.tui import THEME_ORDER, collect_tui_snapshot, run_tui
from agy_profiles.web_server import create_web_server


def _parse_bool(raw: str) -> bool:
    norm = raw.strip().lower()
    if norm in ("1", "true", "yes", "on"):
        return True
    if norm in ("0", "false", "no", "off"):
        return False
    raise argparse.ArgumentTypeError("Expected true/false boolean, got {!r}.".format(raw))


def _build_parser() -> argparse.ArgumentParser:
    common_sub = argparse.ArgumentParser(add_help=False)
    common_sub.add_argument("--root", default=argparse.SUPPRESS, help="Override sandbox profiles root directory.")
    common_sub.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        default=argparse.SUPPRESS,
        help="Print structured JSON output.",
    )

    parser = argparse.ArgumentParser(
        prog="agy-profiles",
        description="Clean-room multi-profile sandbox manager, stdio MCP server, and local web console for Google Antigravity.",
    )
    parser.add_argument("--version", action="version", version="agy-profiles {}".format(__version__))
    parser.add_argument("--root", help="Override sandbox profiles root directory.")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Print structured JSON output.")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", aliases=["ls"], parents=[common_sub], help="List all profiles and host target status.")

    p_create = sub.add_parser("create", parents=[common_sub], help="Create a new isolated sandbox profile.")
    p_create.add_argument("name", help="Profile slug (letters, digits, dot, underscore, hyphen).")
    p_create.add_argument("--label", help="Human display label.")
    p_create.add_argument("--accent", help="6-digit hex accent color (#RRGGBB).")
    p_create.add_argument("--target", "--default-target", choices=("hub", "ide"), default="hub", dest="default_target")
    p_create.add_argument(
        "--links",
        "--link-policy",
        choices=("none", "minimal", "dev"),
        default="dev",
        dest="link_policy",
    )
    p_create.add_argument(
        "--auth",
        "--auth-mode",
        choices=("isolated-file", "system-keychain"),
        default="isolated-file",
        dest="auth_mode",
    )
    p_create.add_argument("--keep-background", type=_parse_bool, default=False, dest="keep_background_alive")
    p_create.add_argument(
        "--inherit-config",
        action="store_true",
        default=True,
        dest="inherit_config",
        help="Inherit sanitized GEMINI.md, settings, projects, plugins, paused automations, and MCP JSON from host .gemini (default).",
    )
    p_create.add_argument(
        "--no-inherit-config",
        action="store_false",
        dest="inherit_config",
        help="Create a clean-room sandbox without inheriting host .gemini customizations.",
    )

    p_inspect = sub.add_parser("inspect", parents=[common_sub], help="Inspect permissions, locks, and Evidence for a profile.")
    p_inspect.add_argument("name")

    p_update = sub.add_parser("update", parents=[common_sub], help="Update profile settings and reconcile isolation.")
    p_update.add_argument("name")
    p_update.add_argument("--label")
    p_update.add_argument("--accent")
    p_update.add_argument("--target", "--default-target", choices=("hub", "ide"), dest="default_target")
    p_update.add_argument("--links", "--link-policy", choices=("none", "minimal", "dev"), dest="link_policy")
    p_update.add_argument("--auth", "--auth-mode", choices=("isolated-file", "system-keychain"), dest="auth_mode")
    p_update.add_argument("--keep-background", type=_parse_bool, default=None, dest="keep_background_alive")

    p_launch = sub.add_parser(
        "launch",
        aliases=["open", "run"],
        parents=[common_sub],
        help="Launch a sandboxed Antigravity instance.",
    )
    p_launch.add_argument("name")
    p_launch.add_argument("--target", choices=("hub", "ide"))
    p_launch.add_argument("--workspace")

    p_stop = sub.add_parser("stop", parents=[common_sub], help="Stop verified running processes for a profile.")
    p_stop.add_argument("name")
    p_stop.add_argument("--target", choices=("hub", "ide", "all"), default="all")
    p_stop.add_argument("--timeout", type=float, default=5.0)

    p_repair = sub.add_parser(
        "repair",
        parents=[common_sub],
        help="Remove stale lock files and reconcile .zshenv permissions.",
    )
    p_repair.add_argument("name")
    p_repair.add_argument("--target", choices=("hub", "ide"))

    p_clone = sub.add_parser("clone", parents=[common_sub], help="Clone a stopped profile to a new profile slug.")
    p_clone.add_argument("source")
    p_clone.add_argument("target")
    p_clone.add_argument("--label")
    p_clone.add_argument(
        "--fresh-auth",
        action="store_true",
        default=False,
        dest="fresh_auth",
        help="Strip OAuth tokens so the cloned profile signs into a new Google account.",
    )

    p_rename = sub.add_parser(
        "rename",
        parents=[common_sub],
        help="Rename a profile slug and display label while keeping OAuth login intact.",
    )
    p_rename.add_argument("source")
    p_rename.add_argument("target")
    p_rename.add_argument("--label")
    p_rename.add_argument(
        "--restart",
        action="store_true",
        help="Stop active target processes before renaming and relaunch afterwards.",
    )

    p_del = sub.add_parser("delete", aliases=["rm"], parents=[common_sub], help="Delete a sandbox profile.")
    p_del.add_argument("name")
    p_del.add_argument("--force-stop", action="store_true", default=False)
    p_del.add_argument("--yes", action="store_true", default=False)

    p_launcher = sub.add_parser(
        "launcher",
        parents=[common_sub],
        help="Build or remove macOS Spotlight/Dock .app launchers.",
    )
    l_sub = p_launcher.add_subparsers(dest="launcher_action", required=True)
    for act in ("build", "remove"):
        pl = l_sub.add_parser(act, parents=[common_sub])
        pl.add_argument("name")
        pl.add_argument("--target", choices=("hub", "ide"))
        pl.add_argument("--dest")

    p_sync = sub.add_parser(
        "sync",
        parents=[common_sub],
        help="Sync sanitized host projects, automations, plugins, agents, skills, MCP JSON, and handoff context.",
    )
    p_sync.add_argument("name", help="Target profile name.")
    p_sync.add_argument(
        "--automations",
        choices=("paused", "active", "strip"),
        default=None,
        dest="automations_mode",
        help="Automations sync mode: paused (standby default), active (takeover), or strip (remove).",
    )
    p_sync.add_argument("--from", default="host", dest="from_source", help="Handoff source ('host' or profile slug).")
    p_sync.add_argument("--include-sidecars", action="store_true", help="Alias for --automations active.")
    p_sync.add_argument("--sessions", action="store_true", default=True, dest="include_sessions", help="Incrementally copy clickable sidebar and CLI sessions (default: enabled).")
    p_sync.add_argument("--no-sessions", action="store_false", dest="include_sessions", help="Skip copying clickable SQLite sessions.")
    p_sync.add_argument("--session-limit", type=int, default=25, dest="session_limit", help="Maximum recent top-level conversations to copy when --sessions is set (default: 25).")
    p_sync.add_argument("--no-handoff", action="store_true", help="Skip writing ~/.gemini/HANDOFF_CONTEXT.md.")
    p_sync.add_argument("--restart", action="store_true", help="Stop and relaunch the profile after syncing.")
    p_sync.add_argument("--limit", type=int, default=10, help="Maximum recent host conversations for handoff.")

    p_switch = sub.add_parser(
        "switch",
        parents=[common_sub],
        help="Check git cleanliness, sync clickable sessions, setup, and handoff, activate automations, and switch onto a backup profile (or back to 'host').",
    )
    p_switch.add_argument("name", help="Target profile name (or 'host' with --from <profile>).")
    p_switch.add_argument(
        "--automations",
        choices=("active", "paused", "strip"),
        default="active",
        dest="automations_mode",
        help="Automations mode on the target profile during takeover (default: active).",
    )
    p_switch.add_argument("--target", choices=("hub", "ide"), help="Target runtime ('hub' or 'ide').")
    p_switch.add_argument("--workspace", help="Optional git workspace directory to check before switching.")
    p_switch.add_argument("--from", default="host", dest="from_source", help="Handoff source ('host' or profile slug).")
    p_switch.add_argument("--no-sessions", action="store_false", default=True, dest="include_sessions", help="Skip migrating clickable SQLite sidebar sessions during switch.")
    p_switch.add_argument("--session-limit", type=int, default=25, dest="session_limit", help="Maximum recent top-level conversations to migrate (default: 25).")
    p_switch.add_argument("--copy-prompt", action="store_true", default=False, help="Copy resume prompt to macOS clipboard.")
    p_switch.add_argument("--no-launch", action="store_true", default=False, help="Sync and check without launching GUI.")

    p_handoff = sub.add_parser(
        "handoff",
        parents=[common_sub],
        help="Read active Host or profile Antigravity conversations read-only as a resume digest.",
    )
    p_handoff.add_argument("--limit", type=int, default=10, help="Maximum conversations to include.")
    p_handoff.add_argument("--from", default="host", dest="source", help="Read threads from 'host' or a profile slug.")
    sub.add_parser("doctor", parents=[common_sub], help="Check host Antigravity bundles, permissions, and lock health.")
    sub.add_parser(
        "obligations",
        parents=[common_sub],
        help="Run live self-checks against security and isolation obligations.",
    )
    sub.add_parser("mcp", parents=[common_sub], help="Run line-delimited JSON-RPC 2.0 MCP server on stdio.")

    p_web = sub.add_parser("web", parents=[common_sub], help="Run hardened localhost Web Console on 127.0.0.1.")
    p_web.add_argument("--host", default="127.0.0.1", help="Loopback bind host (127.0.0.1 or ::1).")
    p_web.add_argument("--port", type=int, default=47920, help="TCP port (0 selects an ephemeral port).")
    p_web.add_argument("--no-open", action="store_true", default=False, help="Do not open default browser automatically.")
    p_web.add_argument("--sidecar", action="store_true", default=False, help="Run inside Antigravity Hub Aux Pane sidecar gateway.")

    p_watch = sub.add_parser(
        "watch",
        aliases=["top", "tui"],
        parents=[common_sub],
        help="Run SRCL and WebTUI inspired ASCII terminal telemetry dashboard or export SVG cards.",
    )
    p_watch.add_argument(
        "--theme",
        choices=THEME_ORDER,
        default="sacred",
        help="Terminal theme: sacred (default), gothic, catppuccin, amber, or ascii.",
    )
    p_watch.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Refresh interval in seconds during interactive watch mode (default: 2.0).",
    )
    p_watch.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Render a single aligned frame to stdout and exit.",
    )
    p_watch.add_argument(
        "--width",
        type=int,
        default=None,
        help="Override terminal column width (78 to 132).",
    )
    p_watch.add_argument(
        "--redact",
        action="store_true",
        default=False,
        help="Mask home paths and email prefixes for public X and GitHub screenshots.",
    )
    p_watch.add_argument(
        "--export-svg",
        default=None,
        dest="export_svg",
        help="Write a standalone dark-mode terminal window SVG card to this path.",
    )
    p_watch.add_argument(
        "--no-auto-failover",
        action="store_false",
        default=True,
        dest="auto_failover",
        help="Disable automatic quota exhaustion failover during interactive watch mode.",
    )

    p_agy = sub.add_parser(
        "agy",
        aliases=["cli", "resume"],
        parents=[common_sub],
        help="Sync terminal sessions and run 'agy' CLI inside a sandbox profile (or 'host') with Turbo bypass.",
    )
    p_agy.add_argument("name", help="Target profile slug (e.g. work-backup) or 'host'.")
    p_agy.add_argument(
        "--from",
        default=None,
        dest="from_source",
        help="Source profile when returning to 'host' (defaults to first backup profile).",
    )
    p_agy.add_argument(
        "--no-sync",
        action="store_true",
        default=False,
        dest="no_sync",
        help="Skip syncing conversations and settings before launching agy CLI.",
    )
    p_agy.add_argument(
        "--ask-permissions",
        action="store_true",
        default=False,
        dest="ask_permissions",
        help="Do not inject --dangerously-skip-permissions automatically.",
    )
    p_agy.add_argument(
        "--no-remote-control",
        action="store_true",
        default=False,
        dest="no_remote_control",
        help="Do not inject --remote-control for Antigravity Mobile visibility.",
    )
    p_agy.add_argument(
        "--print-env",
        action="store_true",
        default=False,
        dest="print_env",
        help="Print resolved agy command and isolated environment JSON without executing.",
    )

    p_auto = sub.add_parser(
        "auto",
        parents=[common_sub],
        help="Run 'agy' in terminal with Turbo bypass, Antigravity Mobile link, and automatic failover on quota exhaustion.",
    )
    p_auto.add_argument(
        "--ask-permissions",
        action="store_true",
        default=False,
        dest="ask_permissions",
        help="Do not inject --dangerously-skip-permissions automatically.",
    )
    p_auto.add_argument(
        "--no-remote-control",
        action="store_true",
        default=False,
        dest="no_remote_control",
        help="Do not inject --remote-control for Antigravity Mobile visibility.",
    )
    p_auto.add_argument(
        "--no-launch",
        action="store_true",
        default=False,
        dest="no_launch",
        help="Do not launch Desktop Hub GUI when auto-failing over to backup profile.",
    )
    p_auto.add_argument(
        "--print-env",
        action="store_true",
        default=False,
        dest="print_env",
        help="Print resolved auto-failover target and command JSON without executing.",
    )

    p_wd = sub.add_parser(
        "watchdog",
        parents=[common_sub],
        help="Monitor Host Antigravity logs and automatically switch quota onto backup profile when exhausted.",
    )
    p_wd.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds (default: 5.0).")
    p_wd.add_argument("--once", action="store_true", default=False, help="Run a single quota check and exit.")
    p_wd.add_argument("--no-launch", action="store_true", default=False, help="Switch setup and crons without opening GUI.")

    p_daemon = sub.add_parser(
        "daemon",
        aliases=["service"],
        parents=[common_sub],
        help="Install, inspect, or open persistent 24/7 macOS launchd services for watchdog, caffeinate anti-sleep, and Web Console.",
    )
    p_daemon.add_argument(
        "daemon_action",
        nargs="?",
        choices=("install", "status", "restart", "open", "uninstall"),
        default="status",
        help="Daemon lifecycle action: install, status, restart, open, or uninstall (default: status).",
    )
    p_daemon.add_argument("--host", default="127.0.0.1", help="Loopback bind host for Web Console (default: 127.0.0.1).")
    p_daemon.add_argument("--port", type=int, default=47920, help="TCP port for Web Console (default: 47920).")
    p_daemon.add_argument("--interval", type=float, default=5.0, help="Watchdog polling interval in seconds (default: 5.0).")
    p_daemon.add_argument(
        "--no-caffeinate",
        action="store_false",
        default=True,
        dest="prevent_sleep",
        help="Do not wrap watchdog with /usr/bin/caffeinate -i idle sleep guard.",
    )
    p_daemon.add_argument("--no-open", action="store_true", default=False, help="Do not open browser automatically.")
    p_daemon.add_argument("--dry-run", action="store_true", default=False, help="Write plist files without calling launchctl.")

    return parser


def _print_human(command: str, data: Dict[str, Any]) -> None:
    if command in ("list", "ls"):
        print("Storage root: {}".format(data["root"]))
        host_acct = data.get("host_account") or {}
        host_rt = data.get("host_runtime") or {}
        hub_rt = host_rt.get("hub") or {}
        ide_rt = host_rt.get("ide") or {}
        host_crons = int(hub_rt.get("schedule_count") or 0) + int(ide_rt.get("schedule_count") or 0)
        print(
            "Host account: {} | HUB: {} | IDE: {} | {} live {} ({} projects, {} sessions, {} automations, {} plugins, {} agents)".format(
                host_acct.get("email") or "unsigned",
                hub_rt.get("state") or "stopped",
                ide_rt.get("state") or "stopped",
                host_crons,
                "cron" if host_crons == 1 else "crons",
                host_acct.get("projects_count", 0),
                host_acct.get("sessions_count", 0),
                host_acct.get("automations_count", 0),
                host_acct.get("plugins_count", 0),
                host_acct.get("agents_count", 0),
            )
        )
        flow = data.get("flow") or {}
        if flow.get("summary"):
            print("Quota flow: {}".format(flow["summary"]))
        for k, t in data["targets"].items():
            status = "v{}".format(t["version"]) if t["installed"] else "not installed"
            print("Target {}: {} ({})".format(k.upper(), t["display_name"], status))
        profiles = data["profiles"]
        if not profiles:
            print("No profiles found. Create one with 'agy-profiles create work'.")
            return
        print("")
        print(
            "{:<18} {:<18} {:<26} {:<6} {:<10} {:<10}".format(
                "NAME", "LABEL", "ACCOUNT", "TARGET", "HUB", "IDE"
            )
        )
        for entry in profiles:
            m = entry["manifest"]
            rt = entry["runtime"]
            acct_email = (entry.get("account") or {}).get("email") or "unsigned"
            print(
                "{:<18} {:<18} {:<26} {:<6} {:<10} {:<10}".format(
                    m["name"][:18],
                    m["label"][:18],
                    acct_email[:26],
                    m["default_target"].upper(),
                    rt["hub"]["state"],
                    rt["ide"]["state"],
                )
            )
        return

    if command == "switch" and data.get("target_profile") == "host":
        host_acct = data.get("host_account") or {}
        sw = data.get("switch") or {}
        hf = data.get("handoff") or {}
        print(
            "Returned quota to Host ({}) from '{}'.".format(
                host_acct.get("email") or "unsigned",
                data.get("from_source") or "backup",
            )
        )
        sess = data.get("sessions") or {}
        print(
            "Host handoff: {} ({} conversations, {} clickable sessions merged) | Backup automations: paused standby".format(
                hf.get("path") or "unavailable",
                hf.get("count", 0),
                sess.get("synced_sessions", 0),
            )
        )
        gs = sw.get("git_status") or {}
        if gs.get("dirty"):
            mod_count = int(gs.get("modified_count", 0))
            print(
                "Warning: {} has {} uncommitted {}. Check status before continuing on Host.".format(
                    gs.get("workspace"),
                    mod_count,
                    "change" if mod_count == 1 else "changes",
                )
            )
        if sw.get("prompt_copied"):
            print("Resume prompt copied to macOS clipboard (Cmd+V in Main Antigravity chat).")
        if "evidence" in data:
            print("Evidence: {} ({})".format(data["evidence"]["evidence_id"], data["evidence"]["summary"]))
        return

    if command in ("inspect", "create", "update", "clone", "rename", "sync", "switch"):
        m = data["manifest"]
        rt = data["runtime"]
        acct = data.get("account") or {}
        sync_state = data.get("sync_state") or {}
        print("Profile: {} ({})".format(m["name"], m["label"]))
        print("Account: {} ({})".format(acct.get("email") or "unsigned", acct.get("source") or "unknown"))
        print("Target: {} | Links: {} | Auth: {}".format(m["default_target"], m["link_policy"], m["auth_mode"]))
        print("Directory: {}".format(data["paths"]["profile_dir"]))
        print("Hub: {} | IDE: {}".format(rt["hub"]["state"], rt["ide"]["state"]))
        if sync_state:
            print(
                "Setup: {} projects | {} sessions | {} automations ({} active) | {} plugins | {} agents | {} skills | MCP {} | Handoff {}".format(
                    sync_state.get("projects_count", 0),
                    sync_state.get("sessions_count", 0),
                    sync_state.get("automations_count", 0),
                    sync_state.get("automations_enabled", 0),
                    sync_state.get("plugins_count", 0),
                    sync_state.get("agents_count", 0),
                    sync_state.get("skills_count", 0),
                    "yes" if sync_state.get("mcp_present") else "no",
                    "yes" if sync_state.get("handoff_present") else "no",
                )
            )
        if "sync" in data:
            sy = data["sync"]
            print(
                "Synced: {} copied | {} sessions | {} automations ({}, {} active) | {} pruned | {} secrets redacted | {} sidecars stripped".format(
                    len(sy.get("copied") or []),
                    sy.get("sessions_synced", 0),
                    sy.get("automations_synced", 0),
                    sy.get("automations_mode", "paused"),
                    sy.get("automations_enabled", 0),
                    sy.get("pruned_entries", 0),
                    sy.get("redacted_secrets", 0),
                    sy.get("stripped_sidecars", 0),
                )
            )
        if "switch" in data:
            sw = data["switch"]
            gs = sw.get("git_status") or {}
            if gs.get("dirty"):
                mod_count = int(gs.get("modified_count", 0))
                print(
                    "Warning: {} has {} uncommitted {}. Pause edits before continuing in {}.".format(
                        gs.get("workspace"),
                        mod_count,
                        "change" if mod_count == 1 else "changes",
                        m["name"],
                    )
                )
            if sw.get("prompt_copied"):
                print("Resume prompt copied to macOS clipboard (Cmd+V in the new chat).")
        if "evidence" in data:
            print("Evidence: {} ({})".format(data["evidence"]["evidence_id"], data["evidence"]["summary"]))
        return

    if command == "handoff":
        print(
            "Source: {} ({})".format(
                data.get("source") or "host",
                data.get("source_account") or data.get("host_account") or "unsigned",
            )
        )
        print("Available: {} | Conversations: {}".format(data.get("available"), data.get("count", 0)))
        for idx, item in enumerate(data.get("conversations") or [], start=1):
            print(
                "{}. [{}] {} ({})".format(
                    idx,
                    item.get("project") or "General",
                    item.get("title") or "Untitled",
                    item.get("status") or "idle",
                )
            )
            detail = item.get("last_user_request") or item.get("last_agent_summary") or ""
            if detail:
                print("   {}".format(detail))
        if data.get("resume_prompt"):
            print("")
            print("Resume prompt:")
            print(data["resume_prompt"])
        return

    if command in ("launch", "open", "run"):
        if data.get("already_running"):
            print("Profile '{}' ({}) already running (PIDs: {}).".format(data["profile"], data["target"], data["pids"]))
        else:
            print("Launched '{}' ({}) with PID {}.".format(data["profile"], data["target"], data["pid"]))
        return

    if command == "stop":
        print("Stopped {} (signaled: {}, forced: {}).".format(data["profile"], data["signaled_pids"], data["forced_pids"]))
        return

    if command == "repair":
        print("Repaired '{}': removed locks {}.".format(data["profile"], data["locks_removed"]))
        return

    if command in ("delete", "rm"):
        print("Deleted profile '{}'.".format(data["profile"]))
        return

    if command == "launcher":
        if "removed" in data:
            print("Launcher removed ({}): {}".format(data["removed"], data["bundle_path"]))
        else:
            print("Built launcher: {}".format(data["bundle_path"]))
        return

    if command == "doctor":
        for chk in data["checks"]:
            print("[{:<4}] {:<18} {}".format(chk["status"].upper(), chk["id"], chk["detail"]))
        return

    if command == "obligations":
        s = data["summary"]
        print("Ledger {}: {}/{} closed, {} failed".format(data["ledger_id"], s["closed"], s["total"], s["failed"]))
        for item in data["items"]:
            print("[{:<6}] {:<32} ({})".format(item["status"].upper(), item["obligation_id"], item["owner_module"]))
        return

    print(json.dumps(data, indent=2))


def _split_agy_cli_argv(raw_argv: List[str]) -> Tuple[List[str], List[str]]:
    """Separate wrapper flags for 'agy'/'cli'/'resume'/'auto' from passthrough flags for the agy binary."""
    idx = 0
    sub_idx: Optional[int] = None
    while idx < len(raw_argv):
        tok = raw_argv[idx]
        if tok == "--root" and idx + 1 < len(raw_argv):
            idx += 2
            continue
        if tok.startswith("--root=") or tok in ("--json", "-h", "--help", "--version"):
            idx += 1
            continue
        if not tok.startswith("-"):
            sub_idx = idx
            break
        idx += 1

    if sub_idx is None or raw_argv[sub_idx] not in ("agy", "cli", "resume", "auto"):
        return raw_argv, []

    sub_name = raw_argv[sub_idx]
    prefix = list(raw_argv[: sub_idx + 1])
    rest = raw_argv[sub_idx + 1 :]
    if rest and rest[0] in ("-h", "--help"):
        return raw_argv, []

    kept: List[str] = []
    passthrough: List[str] = []
    name_seen = sub_name == "auto"
    r_idx = 0
    while r_idx < len(rest):
        tok = rest[r_idx]
        if tok == "--":
            passthrough.extend(rest[r_idx + 1 :])
            break
        if tok in ("--from", "--root") and r_idx + 1 < len(rest):
            kept.extend([tok, rest[r_idx + 1]])
            r_idx += 2
            continue
        if tok.startswith("--from=") or tok.startswith("--root="):
            kept.append(tok)
            r_idx += 1
            continue
        if tok in ("--no-sync", "--ask-permissions", "--no-remote-control", "--no-launch", "--print-env", "--json"):
            kept.append(tok)
            r_idx += 1
            continue
        if not name_seen and not tok.startswith("-"):
            kept.append(tok)
            name_seen = True
            r_idx += 1
            continue
        passthrough.append(tok)
        r_idx += 1

    return prefix + kept, passthrough


def _prepend_safe_toolchain_path(env: Dict[str, str], host_home: Path) -> None:
    safe_bin_dirs = [
        str(host_home / ".local" / "bin"),
        str(host_home / ".cargo" / "bin"),
        str(host_home / ".bun" / "bin"),
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
    ]
    parts = [p for p in env.get("PATH", "").split(":") if p]
    for bdir in reversed(safe_bin_dirs):
        if Path(bdir).is_dir() and bdir not in parts:
            parts.insert(0, bdir)
    if parts:
        env["PATH"] = ":".join(parts)


def _resolve_agy_binary(real_home: Optional[Path]) -> str:
    home_base = (real_home if real_home is not None else Path.home()).resolve()
    candidates = [
        os.environ.get("AGY_CLI_BIN", "").strip(),
        shutil.which("agy") or "",
        str(home_base / ".local" / "bin" / "agy"),
        "/usr/local/bin/agy",
    ]
    for cand in candidates:
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return str(Path(cand).resolve())
    raise ToolError(
        "target_not_found",
        "Could not locate the 'agy' CLI binary on this machine.",
        "Install Antigravity CLI ('agy') in ~/.local/bin/agy or set AGY_CLI_BIN.",
    )


def _ensure_cli_session_flags(
    args_list: List[str],
    ask_permissions: bool,
    no_remote_control: bool,
    force_session_flags: bool,
) -> List[str]:
    out = list(args_list)
    is_print_mode = any(
        a in ("-p", "--print", "--prompt")
        or a.startswith("--print=")
        or a.startswith("--prompt=")
        for a in out
    )
    is_subcmd = len(out) > 0 and not out[0].startswith("-")
    if not ask_permissions and (force_session_flags or len(out) > 0) and not is_subcmd:
        if "--dangerously-skip-permissions" not in out:
            out.append("--dangerously-skip-permissions")
    if (
        not no_remote_control
        and not is_print_mode
        and not is_subcmd
        and (force_session_flags or len(out) > 0)
    ):
        if "--remote-control" not in out:
            out.append("--remote-control")
    return out


def _run_agy_cli_command(
    ctx: RuntimeContext,
    cmd_alias: str,
    target_name: str,
    from_source: Optional[str],
    no_sync: bool,
    ask_permissions: bool,
    no_remote_control: bool,
    print_env: bool,
    passthrough_args: List[str],
) -> int:
    agy_bin = _resolve_agy_binary(ctx.real_home)
    eff_args = list(passthrough_args)
    if cmd_alias == "resume" and not eff_args:
        eff_args = ["-c"]
    eff_args = _ensure_cli_session_flags(
        eff_args,
        ask_permissions=ask_permissions,
        no_remote_control=no_remote_control,
        force_session_flags=(cmd_alias == "resume"),
    )

    cwd_str = os.getcwd()
    git_info = _inspect_git_dirty(cwd_str)
    host_home = (ctx.real_home if ctx.real_home is not None else Path.home()).resolve()

    if target_name.strip().lower() == "host":
        chosen_from = (from_source or "").strip()
        if not chosen_from and not no_sync:
            listed = call_tool("profile_list", {}, ctx)
            profs = listed.get("profiles") or []
            if profs:
                chosen_from = str(profs[0]["manifest"]["name"])
        sync_summary: Optional[Dict[str, Any]] = None
        if not no_sync and chosen_from:
            ret = call_tool(
                "profile_switch",
                {
                    "name": "host",
                    "from_source": chosen_from,
                    "include_sessions": True,
                    "launch": False,
                },
                ctx,
            )
            sync_summary = ret.get("sessions")
        child_env = os.environ.copy()
        child_env["HOME"] = str(host_home)
        child_env["ZDOTDIR"] = str(host_home)
        _prepend_safe_toolchain_path(child_env, host_home)
        child_env.pop("SSH_CONNECTION", None)
        child_env.pop("ANTIGRAVITY_GEMINI_DIR", None)
        child_env.pop("ANTIGRAVITY_CREDENTIAL_SCOPE", None)
        slot_label = "host"
    else:
        prof_name = validate_profile_name(target_name)
        profile_dir, manifest = load_manifest(ctx.root, prof_name)
        provision_profile_dirs(ctx.root, manifest, real_home=ctx.real_home)
        sync_summary = None
        if not no_sync:
            sy_res = call_tool(
                "profile_sync",
                {
                    "name": prof_name,
                    "from_source": from_source or "host",
                    "automations_mode": "paused",
                    "include_handoff": True,
                    "include_sessions": True,
                    "turbo_bypass": True,
                    "restart": False,
                },
                ctx,
            )
            sync_summary = (sy_res.get("sync") or {}).get("sessions")

        sandbox_home = ensure_within_root(profile_dir, profile_dir / "home")
        child_env = os.environ.copy()
        child_env["HOME"] = str(sandbox_home)
        child_env["ZDOTDIR"] = str(sandbox_home)
        child_env["XDG_CONFIG_HOME"] = str(sandbox_home / ".config")
        child_env["XDG_DATA_HOME"] = str(sandbox_home / ".local" / "share")
        child_env["XDG_CACHE_HOME"] = str(sandbox_home / ".cache")
        child_env["ANTIGRAVITY_GEMINI_DIR"] = str(sandbox_home / ".gemini")
        _prepend_safe_toolchain_path(child_env, host_home)
        if manifest.auth_mode == "isolated-file":
            child_env["SSH_CONNECTION"] = "local"
            scope_file = (
                sandbox_home / "Library" / "Application Support" / "antigravity" / "credential-user-scope"
            )
            if scope_file.is_file():
                scope_val = scope_file.read_text(encoding="utf-8", errors="replace").strip()
                if scope_val:
                    child_env["ANTIGRAVITY_CREDENTIAL_SCOPE"] = scope_val
        else:
            child_env.pop("SSH_CONNECTION", None)
        slot_label = prof_name

    full_cmd = [agy_bin] + eff_args
    if print_env:
        print(
            json.dumps(
                {
                    "slot": slot_label,
                    "command": full_cmd,
                    "cwd": cwd_str,
                    "git_status": git_info,
                    "sessions": sync_summary,
                    "env": {
                        "HOME": child_env.get("HOME"),
                        "ZDOTDIR": child_env.get("ZDOTDIR"),
                        "ANTIGRAVITY_GEMINI_DIR": child_env.get("ANTIGRAVITY_GEMINI_DIR"),
                        "SSH_CONNECTION": child_env.get("SSH_CONNECTION"),
                    },
                },
                indent=2,
            )
        )
        return 0

    if git_info.get("dirty"):
        mod_n = int(git_info.get("modified_count", 0))
        sys.stderr.write(
            "[agyp] Working tree {} has {} uncommitted {} preserved on disk.\n".format(
                cwd_str,
                mod_n,
                "change" if mod_n == 1 else "changes",
            )
        )
    if sync_summary is not None:
        sys.stderr.write(
            "[agyp] Synced sessions ({} Hub, {} CLI) into '{}'. Launching: {}\n".format(
                sync_summary.get("hub_synced_sessions", 0),
                sync_summary.get("cli_synced_sessions", 0),
                slot_label,
                " ".join([Path(agy_bin).name] + eff_args),
            )
        )
    sys.stderr.flush()
    proc = subprocess.run(full_cmd, env=child_env, cwd=cwd_str, check=False)
    return int(proc.returncode)


def _run_auto_terminal_failover(
    ctx: RuntimeContext,
    ask_permissions: bool,
    no_remote_control: bool,
    no_launch: bool,
    print_env: bool,
    passthrough_args: List[str],
) -> int:
    """Run 'agy' on the active quota slot and auto-failover to backup profile if Host quota exhausts."""
    overview = call_tool("profile_list", {}, ctx)
    flow = overview.get("flow") or {}
    profiles = overview.get("profiles") or []
    active_owner = str(flow.get("active_owner") or "host")
    eff_args = _ensure_cli_session_flags(
        passthrough_args,
        ask_permissions=ask_permissions,
        no_remote_control=no_remote_control,
        force_session_flags=True,
    )

    if active_owner != "host" and any(p["manifest"]["name"] == active_owner for p in profiles):
        return _run_agy_cli_command(
            ctx,
            cmd_alias="agy",
            target_name=active_owner,
            from_source="host",
            no_sync=False,
            ask_permissions=ask_permissions,
            no_remote_control=no_remote_control,
            print_env=print_env,
            passthrough_args=eff_args,
        )

    log_paths = host_quota_log_paths(ctx.real_home)
    offsets_before = snapshot_log_offsets(log_paths)
    rc = _run_agy_cli_command(
        ctx,
        cmd_alias="agy",
        target_name="host",
        from_source=None,
        no_sync=True,
        ask_permissions=ask_permissions,
        no_remote_control=no_remote_control,
        print_env=print_env,
        passthrough_args=eff_args,
    )
    if print_env or not profiles:
        return rc

    exhausted, reason, _ = scan_new_log_bytes_for_quota_exhaustion(
        log_paths,
        offsets_before,
        initialize_at_eof=False,
    )
    if not exhausted:
        return rc

    backup_slug = str(profiles[0]["manifest"]["name"])
    sys.stderr.write(
        "\n[agyp auto] Host quota exhausted ({}). Failing over automatically to '{}'...\n".format(
            reason or "RESOURCE_EXHAUSTED",
            backup_slug,
        )
    )
    sys.stderr.flush()
    custom_test_bin = bool(os.environ.get("AGY_CLI_BIN", "").strip())
    should_launch_hub = (not no_launch) and (not custom_test_bin)
    call_tool(
        "profile_switch",
        {
            "name": backup_slug,
            "automations_mode": "active",
            "include_sessions": True,
            "copy_prompt": True,
            "launch": should_launch_hub,
        },
        ctx,
    )
    resume_args = ["-c"] if "-c" not in eff_args and "--continue" not in eff_args else []
    return _run_agy_cli_command(
        ctx,
        cmd_alias="resume",
        target_name=backup_slug,
        from_source="host",
        no_sync=True,
        ask_permissions=ask_permissions,
        no_remote_control=no_remote_control,
        print_env=False,
        passthrough_args=resume_args + eff_args,
    )


def main(argv: Optional[List[str]] = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parsed_argv, passthrough_args = _split_agy_cli_argv(raw_argv)
    parser = _build_parser()
    args = parser.parse_args(parsed_argv)
    root = resolve_profiles_root(getattr(args, "root", None))
    cli_bin = os.path.realpath(sys.argv[0]) if sys.argv else None
    real_home_env = os.environ.get("AGY_PROFILES_REAL_HOME", "").strip()
    real_home = Path(real_home_env).expanduser() if real_home_env else None
    ctx = RuntimeContext(root=root, real_home=real_home, cli_bin_path=cli_bin)

    try:
        cmd = args.command
        if cmd == "mcp":
            return serve_mcp_stdio(ctx)

        if cmd in ("agy", "cli", "resume"):
            return _run_agy_cli_command(
                ctx,
                cmd_alias=cmd,
                target_name=args.name,
                from_source=args.from_source,
                no_sync=bool(args.no_sync),
                ask_permissions=bool(args.ask_permissions),
                no_remote_control=bool(args.no_remote_control),
                print_env=bool(args.print_env),
                passthrough_args=passthrough_args,
            )

        if cmd == "auto":
            return _run_auto_terminal_failover(
                ctx,
                ask_permissions=bool(args.ask_permissions),
                no_remote_control=bool(args.no_remote_control),
                no_launch=bool(args.no_launch),
                print_env=bool(args.print_env),
                passthrough_args=passthrough_args,
            )

        if cmd in ("daemon", "service"):
            act = args.daemon_action
            if act in ("install", "restart"):
                d_res = install_daemons(
                    ctx,
                    host=args.host,
                    port=args.port,
                    interval_sec=args.interval,
                    prevent_sleep=bool(args.prevent_sleep),
                    open_browser=not bool(args.no_open),
                    dry_run=bool(args.dry_run),
                )
                if args.as_json:
                    print(json.dumps(d_res, indent=2))
                else:
                    print("Installed 24/7 launchd services:")
                    print("  Watchdog plist: {} (caffeinate idle guard={})".format(d_res["watchdog_plist"], d_res["prevent_idle_sleep"]))
                    print("  Web plist:      {} (listening={})".format(d_res["web_plist"], d_res["web_listening"]))
                    print("  Persistent Console URL: {}".format(d_res["owner_url"]))
                return 0
            if act == "open":
                o_res = open_daemon_console(
                    ctx,
                    host=args.host,
                    port=args.port,
                    open_browser=not bool(args.no_open),
                )
                if args.as_json:
                    print(json.dumps(o_res, indent=2))
                else:
                    print("Persistent Console URL: {}".format(o_res["owner_url"]))
                return 0
            if act == "uninstall":
                u_res = uninstall_daemons(ctx, dry_run=bool(args.dry_run))
                if args.as_json:
                    print(json.dumps(u_res, indent=2))
                else:
                    print("Uninstalled launchd services ({} plists removed).".format(len(u_res["removed_plists"])))
                return 0
            s_res = daemon_status(ctx, host=args.host, port=args.port)
            if args.as_json:
                print(json.dumps(s_res, indent=2))
            else:
                wd_s = s_res["watchdog"]
                wb_s = s_res["web"]
                print(
                    "Watchdog daemon: loaded={} pid={} lock_pid={} caffeinate_idle_guard={}".format(
                        wd_s["launchd"]["loaded"],
                        wd_s["launchd"]["pid"],
                        wd_s["lock"]["pid"],
                        wd_s["caffeinate_idle_guard"],
                    )
                )
                print(
                    "Web Console:     loaded={} pid={} listening={} origin={}".format(
                        wb_s["launchd"]["loaded"],
                        wb_s["launchd"]["pid"],
                        wb_s["listening"],
                        wb_s["origin"],
                    )
                )
                print("Persistent Console URL: {}".format(wb_s["owner_url"]))
            return 0

        if cmd == "watchdog":
            interval_s = max(1.0, float(args.interval))
            do_launch = not bool(args.no_launch)
            if args.once:
                wd_res = poll_auto_failover_once(ctx, call_tool, launch=do_launch)
                if args.as_json:
                    print(json.dumps(wd_res, indent=2))
                elif wd_res.get("switched_to"):
                    print(
                        "Quota exhausted detected ({}); automatically switched onto '{}'.".format(
                            wd_res.get("reason") or "exhausted",
                            wd_res["switched_to"],
                        )
                    )
                else:
                    print(
                        "Quota watchdog OK (owner={}, initialized={}).".format(
                            wd_res.get("active_owner_before"),
                            wd_res.get("initialized"),
                        )
                    )
                return 0
            lock_fh = acquire_watchdog_lock(root)
            if lock_fh is None:
                print("Another agyp watchdog instance is already active; exiting cleanly.", flush=True)
                return 0
            print(
                "AGY Profiles Quota Watchdog active (polling every {:.1f}s). Press Ctrl+C to stop.".format(interval_s),
                flush=True,
            )
            try:
                while True:
                    wd_res = poll_auto_failover_once(ctx, call_tool, launch=do_launch)
                    if wd_res.get("switched_to"):
                        print(
                            "[{}] Auto-switched quota onto '{}' ({})".format(
                                wd_res["checked_at"],
                                wd_res["switched_to"],
                                wd_res.get("reason") or "exhausted",
                            ),
                            flush=True,
                        )
                    time.sleep(interval_s)
            except KeyboardInterrupt:
                print("\nStopped Quota Watchdog.")
            finally:
                lock_fh.close()
            return 0

        if cmd in ("watch", "top", "tui"):
            if args.as_json:
                print(json.dumps(collect_tui_snapshot(ctx, selected_slot="host"), indent=2))
                return 0
            return run_tui(
                ctx,
                theme_slug=args.theme,
                interval_sec=args.interval,
                once=bool(args.once),
                width=args.width,
                redact=bool(args.redact),
                export_svg=args.export_svg,
                auto_failover=bool(args.auto_failover),
            )

        if cmd == "web":
            sidecar_mode = bool(args.sidecar)
            if not sidecar_mode and not args.no_open and args.port > 0 and _is_tcp_listening(args.host, args.port):
                existing_url = get_owner_console_url(ctx, host=args.host, port=args.port)
                print("AGY Profiles Web Console already active on http://{}:{}".format(args.host, args.port), flush=True)
                print("Authenticated session URL: {}".format(existing_url), flush=True)
                webbrowser.open(existing_url)
                return 0
            httpd = create_web_server(ctx, host=args.host, port=args.port, sidecar_mode=sidecar_mode)
            sec = httpd.security_state
            session_file = root / ".web-session.json"
            if sidecar_mode:
                print("[sidecar] listening on 127.0.0.1:{}".format(sec.port), flush=True)
            else:
                print("AGY Profiles Web Console listening on {}".format(sec.expected_origin), flush=True)
                print("Authenticated session URL: {}".format(sec.owner_tokenized_url), flush=True)
                try:
                    root.mkdir(parents=True, exist_ok=True)
                    os.chmod(str(root), 0o700)
                    atomic_write_json(
                        session_file,
                        {
                            "pid": os.getpid(),
                            "origin": sec.expected_origin,
                            "owner_url": sec.owner_tokenized_url,
                            "started_at": utc_now_iso(),
                        },
                        mode=0o600,
                    )
                except OSError:
                    pass
                if not args.no_open:
                    webbrowser.open(sec.owner_tokenized_url)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nShutting down AGY Profiles Web Console.")
            finally:
                if not sidecar_mode:
                    try:
                        if session_file.is_file():
                            info = json.loads(session_file.read_text(encoding="utf-8"))
                            if info.get("pid") == os.getpid():
                                session_file.unlink()
                    except (OSError, ValueError):
                        pass
                httpd.server_close()
            return 0

        result: Dict[str, Any]
        if cmd in ("list", "ls"):
            result = call_tool("profile_list", {}, ctx)
        elif cmd == "create":
            result = call_tool(
                "profile_create",
                {
                    "name": args.name,
                    "label": args.label,
                    "accent": args.accent,
                    "default_target": args.default_target,
                    "link_policy": args.link_policy,
                    "auth_mode": args.auth_mode,
                    "keep_background_alive": args.keep_background_alive,
                    "inherit_config": args.inherit_config,
                },
                ctx,
            )
        elif cmd == "inspect":
            result = call_tool("profile_inspect", {"name": args.name}, ctx)
        elif cmd == "update":
            payload: Dict[str, Any] = {"name": args.name}
            for field in ("label", "accent", "default_target", "link_policy", "auth_mode", "keep_background_alive"):
                val = getattr(args, field)
                if val is not None:
                    payload[field] = val
            result = call_tool("profile_update", payload, ctx)
        elif cmd in ("launch", "open", "run"):
            result = call_tool(
                "profile_launch",
                {"name": args.name, "target": args.target, "workspace": args.workspace},
                ctx,
            )
        elif cmd == "stop":
            result = call_tool(
                "profile_stop",
                {"name": args.name, "target": args.target, "timeout_sec": args.timeout},
                ctx,
            )
        elif cmd == "repair":
            result = call_tool("profile_repair", {"name": args.name, "target": args.target}, ctx)
        elif cmd == "clone":
            result = call_tool(
                "profile_clone",
                {
                    "source": args.source,
                    "target": args.target,
                    "label": args.label,
                    "fresh_auth": bool(args.fresh_auth),
                },
                ctx,
            )
        elif cmd == "rename":
            result = call_tool(
                "profile_rename",
                {
                    "source": args.source,
                    "target": args.target,
                    "label": args.label,
                    "restart": bool(args.restart),
                },
                ctx,
            )
        elif cmd in ("delete", "rm"):
            confirm = args.yes
            if not confirm:
                if sys.stdin.isatty():
                    answer = input("Delete profile '{}' and its sandbox directory? [y/N]: ".format(args.name))
                    confirm = answer.strip().lower() in ("y", "yes")
                else:
                    raise ToolError(
                        "invalid_argument",
                        "Non-interactive deletion requires '--yes'.",
                        "Re-run with '--yes' to confirm profile removal.",
                    )
            if not confirm:
                print("Cancelled.")
                return 1
            result = call_tool(
                "profile_delete",
                {"name": args.name, "force_stop": args.force_stop, "confirm": True},
                ctx,
            )
        elif cmd == "launcher":
            tool_name = "launcher_build" if args.launcher_action == "build" else "launcher_remove"
            result = call_tool(
                tool_name,
                {"name": args.name, "target": args.target, "dest": args.dest},
                ctx,
            )
        elif cmd == "sync":
            sync_payload: Dict[str, Any] = {
                "name": args.name,
                "include_sidecars": bool(args.include_sidecars),
                "include_handoff": not bool(args.no_handoff),
                "include_sessions": bool(args.include_sessions),
                "session_limit": int(args.session_limit),
                "from_source": args.from_source,
                "restart": bool(args.restart),
                "limit": int(args.limit),
            }
            if args.automations_mode is not None:
                sync_payload["automations_mode"] = args.automations_mode
            result = call_tool("profile_sync", sync_payload, ctx)
        elif cmd == "switch":
            result = call_tool(
                "profile_switch",
                {
                    "name": args.name,
                    "automations_mode": args.automations_mode,
                    "target": args.target,
                    "workspace": args.workspace,
                    "from_source": args.from_source,
                    "include_sessions": bool(args.include_sessions),
                    "session_limit": int(args.session_limit),
                    "copy_prompt": bool(args.copy_prompt),
                    "launch": not bool(args.no_launch),
                },
                ctx,
            )
        elif cmd == "handoff":
            result = call_tool("host_handoff", {"limit": int(args.limit), "source": args.source}, ctx)
        elif cmd == "doctor":
            result = call_tool("system_doctor", {}, ctx)
        elif cmd == "obligations":
            result = call_tool("obligations_verify", {}, ctx)
        else:
            raise ToolError("invalid_argument", "Unknown command {!r}.".format(cmd))

        if args.as_json:
            print(json.dumps(result, indent=2))
        else:
            _print_human(cmd, result)
        return 0
    except ToolError as exc:
        if args.as_json:
            print(json.dumps(exc.to_dict(), indent=2), file=sys.stderr)
        else:
            print("Error [{}]: {}".format(exc.code, exc.message), file=sys.stderr)
            if exc.remediation:
                print("Remediation: {}".format(exc.remediation), file=sys.stderr)
        return 1
