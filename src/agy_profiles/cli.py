"""Command-line interface entrypoint for agy-profiles and agyp."""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from typing import Any, Dict, List, Optional

from agy_profiles import __version__
from agy_profiles.config import resolve_profiles_root
from agy_profiles.errors import ToolError
from agy_profiles.mcp_server import serve_mcp_stdio
from agy_profiles.tools import RuntimeContext, call_tool
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
        default="minimal",
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
        default=False,
        help="Inherit non-secret GEMINI.md and sanitized settings/MCP JSON from host .gemini.",
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
        help="Sync sanitized host projects, plugins, agents, skills, MCP JSON, and handoff context.",
    )
    p_sync.add_argument("name", help="Target profile name.")
    p_sync.add_argument("--include-sidecars", action="store_true", help="Preserve host project sidecar schedules.")
    p_sync.add_argument("--no-handoff", action="store_true", help="Skip writing ~/.gemini/HANDOFF_CONTEXT.md.")
    p_sync.add_argument("--restart", action="store_true", help="Stop and relaunch the profile after syncing.")
    p_sync.add_argument("--limit", type=int, default=10, help="Maximum recent host conversations for handoff.")
    p_handoff = sub.add_parser(
        "handoff",
        parents=[common_sub],
        help="Read active host Antigravity conversations read-only as a resume digest.",
    )
    p_handoff.add_argument("--limit", type=int, default=10, help="Maximum host conversations to include.")
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

    return parser


def _print_human(command: str, data: Dict[str, Any]) -> None:
    if command in ("list", "ls"):
        print("Storage root: {}".format(data["root"]))
        host_acct = data.get("host_account") or {}
        print(
            "Host account: {} ({} projects, {} plugins, {} agents)".format(
                host_acct.get("email") or "unsigned",
                host_acct.get("projects_count", 0),
                host_acct.get("plugins_count", 0),
                host_acct.get("agents_count", 0),
            )
        )
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

    if command in ("inspect", "create", "update", "clone", "sync"):
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
                "Setup: {} projects | {} plugins | {} agents | {} skills | MCP {} | Handoff {}".format(
                    sync_state.get("projects_count", 0),
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
                "Synced: {} copied | {} secrets redacted | {} sidecars stripped | restarted={}".format(
                    len(sy.get("copied") or []),
                    sy.get("redacted_secrets", 0),
                    sy.get("stripped_sidecars", 0),
                    data.get("restarted", False),
                )
            )
        if "evidence" in data:
            print("Evidence: {} ({})".format(data["evidence"]["evidence_id"], data["evidence"]["summary"]))
        return

    if command == "handoff":
        print("Host account: {}".format(data.get("host_account") or "unsigned"))
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    root = resolve_profiles_root(args.root)
    cli_bin = os.path.realpath(sys.argv[0]) if sys.argv else None
    ctx = RuntimeContext(root=root, cli_bin_path=cli_bin)

    try:
        cmd = args.command
        if cmd == "mcp":
            return serve_mcp_stdio(ctx)

        if cmd == "web":
            httpd = create_web_server(ctx, host=args.host, port=args.port)
            sec = httpd.security_state
            print("AGY Profiles Web Console listening on {}".format(sec.expected_origin), flush=True)
            print("Authenticated session URL: {}".format(sec.tokenized_url), flush=True)
            if not args.no_open:
                webbrowser.open(sec.tokenized_url)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nShutting down AGY Profiles Web Console.")
            finally:
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
                {"source": args.source, "target": args.target, "label": args.label},
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
            result = call_tool(
                "profile_sync",
                {
                    "name": args.name,
                    "include_sidecars": bool(args.include_sidecars),
                    "include_handoff": not bool(args.no_handoff),
                    "restart": bool(args.restart),
                    "limit": int(args.limit),
                },
                ctx,
            )
        elif cmd == "handoff":
            result = call_tool("host_handoff", {"limit": int(args.limit)}, ctx)
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
