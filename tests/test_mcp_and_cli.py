"""Tests for stdio MCP JSON-RPC 2.0 server and CLI subcommands."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agy_profiles.cli import main as cli_main
from agy_profiles.isolation import REDACTED_MARKER, create_safe_link
from agy_profiles.macos_launcher import resolve_launcher_bundle_path, verify_launcher_signature
from agy_profiles.mcp_server import handle_mcp_request, serve_mcp_stdio
from agy_profiles.process_guard import HOST_DATA_DIR_RELPATHS
from agy_profiles.tools import RuntimeContext, call_tool


class McpAndCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "profiles"
        self.root.mkdir(mode=0o700)
        self.fake_home = Path(self.tmp.name).resolve() / "fake-home"
        self.fake_home.mkdir(mode=0o700)
        self._old_real_home = os.environ.get("AGY_PROFILES_REAL_HOME")
        os.environ["AGY_PROFILES_REAL_HOME"] = str(self.fake_home)
        self.ctx = RuntimeContext(root=self.root, real_home=self.fake_home)

    def tearDown(self) -> None:
        if self._old_real_home is None:
            os.environ.pop("AGY_PROFILES_REAL_HOME", None)
        else:
            os.environ["AGY_PROFILES_REAL_HOME"] = self._old_real_home
        self.tmp.cleanup()

    def test_mcp_stdio_roundtrip(self) -> None:
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "profile_create", "arguments": {"name": "mcp-work", "link_policy": "none"}},
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "obligations_verify", "arguments": {}},
            },
        ]
        stdin_buf = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
        stdout_buf = io.StringIO()
        serve_mcp_stdio(self.ctx, stdin=stdin_buf, stdout=stdout_buf)

        responses = [json.loads(line) for line in stdout_buf.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(responses), 4)

        self.assertEqual(responses[0]["id"], 1)
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2024-11-05")

        tools = responses[1]["result"]["tools"]
        tool_names = {t["name"] for t in tools}
        self.assertIn("profile_create", tool_names)
        self.assertIn("obligations_verify", tool_names)
        self.assertIn("profile_sync", tool_names)
        self.assertIn("profile_switch", tool_names)
        self.assertIn("profile_rename", tool_names)
        self.assertIn("host_handoff", tool_names)
        self.assertGreaterEqual(len(tool_names), 17)

        create_payload = json.loads(responses[2]["result"]["content"][0]["text"])
        self.assertFalse(responses[2]["result"].get("isError", False))
        self.assertEqual(create_payload["manifest"]["name"], "mcp-work")

        obl_payload = json.loads(responses[3]["result"]["content"][0]["text"])
        self.assertEqual(obl_payload["summary"]["failed"], 0)

    def test_mcp_parse_and_tool_errors(self) -> None:
        bad_json = handle_mcp_request("{bad", self.ctx)
        self.assertEqual(bad_json["error"]["code"], -32700)

        unknown_tool = handle_mcp_request(
            json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "nope", "arguments": {}}}),
            self.ctx,
        )
        self.assertTrue(unknown_tool["result"]["isError"])

    def test_cli_end_to_end_json_commands(self) -> None:
        commands = [
            ["--root", str(self.root), "create", "cli-one", "--label", "CLI One", "--links", "none", "--json"],
            ["--root", str(self.root), "list", "--json"],
            ["--root", str(self.root), "inspect", "cli-one", "--json"],
            ["--root", str(self.root), "update", "cli-one", "--label", "CLI Updated", "--json"],
            ["--root", str(self.root), "clone", "cli-one", "cli-two", "--json"],
            ["--root", str(self.root), "repair", "cli-one", "--json"],
            ["--root", str(self.root), "doctor", "--json"],
            ["--root", str(self.root), "sync", "cli-one", "--no-handoff", "--json"],
            ["--root", str(self.root), "handoff", "--limit", "5", "--json"],
            ["--root", str(self.root), "obligations", "--json"],
            ["--root", str(self.root), "delete", "cli-two", "--yes", "--json"],
        ]
        for args in commands:
            buf = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = buf
                rc = cli_main(args)
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0, msg="CLI failed for {}".format(args))
            parsed = json.loads(buf.getvalue())
            self.assertIsInstance(parsed, dict)

    def test_profile_rename_preserves_credentials_and_relocks_zshenv(self) -> None:
        rc = 0
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            rc = cli_main(
                [
                    "--root",
                    str(self.root),
                    "create",
                    "acct-old",
                    "--label",
                    "Acct Old",
                    "--links",
                    "none",
                    "--no-inherit-config",
                    "--json",
                ]
            )
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)

        old_dir = self.root / "acct-old"
        oauth_file = old_dir / "home" / ".gemini" / "jetski-standalone-oauth-token"
        oauth_file.write_text(json.dumps({"id_token_email": "backup@example.com"}), encoding="utf-8")
        os.chmod(str(oauth_file), 0o600)

        cred_scope = old_dir / "home" / "Library" / "Application Support" / "antigravity" / "credential-user-scope"
        cred_scope.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(cred_scope.parent), 0o700)
        cred_scope.write_text("user-scope-token", encoding="utf-8")
        os.chmod(str(cred_scope), 0o600)

        host_mcp = self.fake_home / ".gemini" / "antigravity" / "mcp_config.json"
        host_mcp.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(host_mcp.parent), 0o700)
        host_mcp.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")

        old_cfg = old_dir / "home" / ".gemini" / "config" / "mcp_config.json"
        old_cfg.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(old_cfg.parent), 0o700)
        old_cfg.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")

        old_link = old_dir / "home" / ".gemini" / "antigravity" / "mcp_config.json"
        old_link.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(old_link.parent), 0o700)
        created_symlink = True
        try:
            os.symlink(str(old_cfg), str(old_link))
        except OSError as exc:
            if sys.platform == "win32" and getattr(exc, "winerror", None) == 1314:
                created_symlink = False
                create_safe_link(old_cfg, old_link)
            else:
                raise

        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            rc = cli_main(
                [
                    "--root",
                    str(self.root),
                    "rename",
                    "acct-old",
                    "backup-box",
                    "--label",
                    "backup@example.com",
                    "--json",
                ]
            )
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        renamed = json.loads(buf.getvalue())
        self.assertEqual(renamed["renamed_from"], "acct-old")
        self.assertEqual(renamed["manifest"]["name"], "backup-box")
        self.assertEqual(renamed["manifest"]["label"], "backup@example.com")
        self.assertEqual(renamed["account"]["email"], "backup@example.com")
        self.assertFalse(old_dir.exists())

        new_dir = self.root / "backup-box"
        new_cred = new_dir / "home" / "Library" / "Application Support" / "antigravity" / "credential-user-scope"
        self.assertTrue(new_cred.is_file())
        self.assertEqual(new_cred.read_text(encoding="utf-8"), "user-scope-token")
        zshenv_text = (new_dir / "home" / ".zshenv").read_text(encoding="utf-8")
        expected_home = (new_dir / "home").resolve()
        self.assertIn("export HOME=", zshenv_text)
        self.assertIn("export ZDOTDIR=", zshenv_text)
        self.assertIn(str(expected_home), zshenv_text)

        new_link = new_dir / "home" / ".gemini" / "antigravity" / "mcp_config.json"
        if created_symlink:
            self.assertTrue(new_link.is_symlink())
            self.assertEqual(os.readlink(str(new_link)), str(new_dir / "home" / ".gemini" / "config" / "mcp_config.json"))
        else:
            self.assertTrue(new_link.is_file())
        sync_res = call_tool("profile_sync", {"name": "backup-box", "include_handoff": False}, self.ctx)
        self.assertEqual(sync_res["manifest"]["name"], "backup-box")

    def test_cli_create_defaults_to_dev_links_and_inherit_config(self) -> None:
        (self.fake_home / ".agents" / "skills" / "demo").mkdir(parents=True)
        (self.fake_home / ".gemini" / "config").mkdir(parents=True)
        (self.fake_home / ".gemini" / "GEMINI.md").write_text("# Host Rules\n", encoding="utf-8")

        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            rc = cli_main(["--root", str(self.root), "create", "default-box", "--json"])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        created = json.loads(buf.getvalue())
        self.assertEqual(created["manifest"]["link_policy"], "dev")
        self.assertTrue((self.root / "default-box" / "home" / ".agents").exists())
        self.assertTrue((self.root / "default-box" / "home" / ".gemini" / "GEMINI.md").is_file())

    def test_profile_update_reconciles_signed_launcher_on_label_change(self) -> None:
        if sys.platform != "darwin":
            self.skipTest("macOS .app launcher test runs on Darwin only")
        call_tool(
            "profile_create",
            {"name": "sig-box", "label": "Old Label", "link_policy": "none"},
            self.ctx,
        )
        built = call_tool("launcher_build", {"name": "sig-box", "target": "hub"}, self.ctx)
        self.assertTrue(built["signed"])
        old_bundle = Path(built["bundle_path"])
        self.assertTrue(verify_launcher_signature(old_bundle))

        updated = call_tool(
            "profile_update",
            {"name": "sig-box", "label": "Renamed Label"},
            self.ctx,
        )
        self.assertFalse(old_bundle.exists())
        new_bundle = resolve_launcher_bundle_path(
            "sig-box",
            "Renamed Label",
            "hub",
            dest_dir=self.fake_home / "Applications",
        )
        self.assertTrue(new_bundle.is_dir())
        self.assertTrue(verify_launcher_signature(new_bundle))
        self.assertTrue(updated["launchers"]["hub"])

    def test_clone_fresh_auth_strips_oauth_keeps_customizations(self) -> None:
        call_tool("profile_create", {"name": "acct-src", "label": "Src", "link_policy": "none"}, self.ctx)
        src_dir = self.root / "acct-src"
        (src_dir / "home" / ".gemini" / "config").mkdir(parents=True, exist_ok=True)
        (src_dir / "home" / ".gemini" / "config" / "mcp_config.json").write_text('{"mcpServers":{}}\n', encoding="utf-8")
        (src_dir / "home" / ".gemini" / "jetski-standalone-oauth-token").write_text(
            json.dumps({"id_token_email": "src@example.com"}),
            encoding="utf-8",
        )
        cred_scope = src_dir / "home" / "Library" / "Application Support" / "antigravity" / "credential-user-scope"
        cred_scope.parent.mkdir(parents=True, exist_ok=True)
        cred_scope.write_text("secret-scope", encoding="utf-8")
        (src_dir / "data" / "app_storage.json").write_text(
            json.dumps({"agy.onboarding.lastLoginUsername": "src@example.com", "autoCheckForUpdates": "false"}),
            encoding="utf-8",
        )

        src_inst_id = (src_dir / "home" / ".gemini" / "installation_id").read_text(encoding="utf-8").strip()
        (src_dir / "home" / ".gemini" / "antigravity").mkdir(parents=True, exist_ok=True)
        (src_dir / "home" / ".gemini" / "antigravity" / "antigravity_state.pbtxt").write_text(
            'post_onboarding: true\ninstallation_uuid: "old-src-uuid"\n',
            encoding="utf-8",
        )

        cloned = call_tool(
            "profile_clone",
            {"source": "acct-src", "target": "acct-three", "label": "Account 3", "fresh_auth": True},
            self.ctx,
        )
        self.assertTrue(cloned["fresh_auth"])
        self.assertIsNone(cloned["account"]["email"])
        self.assertFalse(cloned["account"]["oauth_present"])
        dst_dir = self.root / "acct-three"
        dst_inst_id = (dst_dir / "home" / ".gemini" / "installation_id").read_text(encoding="utf-8").strip()
        self.assertTrue(dst_inst_id)
        self.assertNotEqual(dst_inst_id, src_inst_id)
        pb_after = (dst_dir / "home" / ".gemini" / "antigravity" / "antigravity_state.pbtxt").read_text(encoding="utf-8")
        self.assertNotIn("old-src-uuid", pb_after)
        self.assertFalse((dst_dir / "home" / ".gemini" / "jetski-standalone-oauth-token").exists())
        self.assertFalse((dst_dir / "home" / "Library" / "Application Support" / "antigravity" / "credential-user-scope").exists())
        self.assertTrue((dst_dir / "home" / ".gemini" / "config" / "mcp_config.json").is_file())
        storage = json.loads((dst_dir / "data" / "app_storage.json").read_text(encoding="utf-8"))
        self.assertEqual(storage.get("autoCheckForUpdates"), "false")
        self.assertNotIn("agy.onboarding.lastLoginUsername", storage)

    def test_profile_switch_checks_git_dirty_and_activates_automations(self) -> None:
        host_gemini = self.fake_home / ".gemini"
        (host_gemini / "config" / "sidecars" / "auto-demo").mkdir(parents=True)
        (host_gemini / "config" / "sidecars" / "auto-demo" / "sidecar.json").write_text(
            json.dumps({"builtin": "schedule", "display_name": "Auto Demo", "args": []}),
            encoding="utf-8",
        )
        (host_gemini / "config" / "config.json").write_text(
            json.dumps({"sidecars": {"auto-demo": {"enabled": True, "schemaVersion": 1}}}),
            encoding="utf-8",
        )

        ws_repo = Path(self.tmp.name).resolve() / "dirty-repo"
        ws_repo.mkdir()
        subprocess.run(["git", "-C", str(ws_repo), "init"], check=True, capture_output=True)
        (ws_repo / "dirty.txt").write_text("uncommitted", encoding="utf-8")

        call_tool("profile_create", {"name": "takeover-box", "label": "Takeover", "link_policy": "none"}, self.ctx)
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            rc = cli_main(
                [
                    "--root",
                    str(self.root),
                    "switch",
                    "takeover-box",
                    "--workspace",
                    str(ws_repo),
                    "--no-launch",
                    "--json",
                ]
            )
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        res = json.loads(buf.getvalue())
        self.assertEqual(res["sync"]["automations_mode"], "active")
        self.assertEqual(res["sync"]["automations_enabled"], 1)
        self.assertTrue(res["switch"]["git_status"]["is_git"])
        self.assertTrue(res["switch"]["git_status"]["dirty"])
        self.assertGreaterEqual(res["switch"]["git_status"]["modified_count"], 1)

        listed_active = call_tool("profile_list", {}, self.ctx)
        self.assertIn("host_runtime", listed_active)
        self.assertEqual(listed_active["flow"]["mode"], "backup_active")
        self.assertEqual(listed_active["flow"]["active_owner"], "takeover-box")

        # Populate a conversation inside takeover-box and return quota back to Host.
        import sqlite3
        from agy_profiles.errors import ToolError

        with self.assertRaises(ToolError):
            call_tool("profile_create", {"name": "host", "link_policy": "none"}, self.ctx)

        prof_antigravity = self.root / "takeover-box" / "home" / ".gemini" / "antigravity"
        prof_antigravity.mkdir(parents=True, exist_ok=True)
        db_file = prof_antigravity / "conversation_summaries.db"
        conn = sqlite3.connect(str(db_file))
        try:
            conn.execute(
                "CREATE TABLE conversation_summaries ("
                "conversation_id TEXT, title TEXT, preview TEXT, "
                "last_modified_time TEXT, workspace_uris TEXT, status TEXT, project_id TEXT)"
            )
            conn.execute(
                "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "conv-return-1",
                    "Backup Sprint Progress",
                    "Finished Phase 2 tests",
                    "2026-11-16T04:00:00Z",
                    json.dumps(["file://{}".format(ws_repo)]),
                    "DONE",
                    "proj-1",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        returned = call_tool(
            "profile_switch",
            {"name": "host", "from_source": "takeover-box", "launch": False},
            self.ctx,
        )
        self.assertEqual(returned["target_profile"], "host")
        self.assertEqual(returned["from_source"], "takeover-box")
        self.assertTrue(returned["handoff"]["written"])
        self.assertEqual(returned["handoff"]["count"], 1)
        host_handoff_md = self.fake_home / ".gemini" / "HANDOFF_CONTEXT.md"
        self.assertTrue(host_handoff_md.is_file())
        self.assertIn("Backup Sprint Progress", host_handoff_md.read_text(encoding="utf-8"))
        self.assertEqual(returned["sync"]["automations_enabled"], 0)
        self.assertEqual(returned["flow"]["mode"], "host_primary")
        _ = REDACTED_MARKER

    def test_tui_themes_exact_column_alignment_and_svg_export(self) -> None:
        from agy_profiles.tui import THEME_ORDER, collect_tui_snapshot, render_tui_lines, visible_len

        call_tool("profile_create", {"name": "tui-box", "label": "TUI Box", "link_policy": "none"}, self.ctx)
        (self.fake_home / "Library" / "Application Support" / "Antigravity").mkdir(parents=True, exist_ok=True)
        (self.fake_home / "Library" / "Application Support" / "Antigravity" / "app_storage.json").write_text(
            json.dumps({"agy.onboarding.lastLoginUsername": "hostdemo@example.com"}),
            encoding="utf-8",
        )

        snap = collect_tui_snapshot(self.ctx, selected_slot="host")
        for slug in THEME_ORDER:
            lines = render_tui_lines(snap, theme_slug=slug, width=96, color=(slug != "ascii"), redact=True)
            self.assertGreater(len(lines), 10)
            for idx, ln in enumerate(lines):
                self.assertEqual(
                    visible_len(ln),
                    96,
                    msg="Theme {} line {} drifted to {} cols".format(slug, idx, visible_len(ln)),
                )
            joined = "\n".join(lines)
            self.assertIn("host***@example.com", joined)
            self.assertNotIn("hostdemo@example.com", joined)
            if slug == "ascii":
                self.assertNotIn("\x1b[", joined)

        svg_path = Path(self.tmp.name).resolve() / "showcase.svg"
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            rc = cli_main(
                [
                    "--root",
                    str(self.root),
                    "top",
                    "--once",
                    "--theme",
                    "sacred",
                    "--width",
                    "96",
                    "--redact",
                    "--export-svg",
                    str(svg_path),
                ]
            )
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc, 0)
        self.assertTrue(svg_path.is_file())
        svg_text = svg_path.read_text(encoding="utf-8")
        self.assertIn("<svg", svg_text)
        self.assertIn("agyp top", svg_text)
        self.assertNotIn("hostdemo@example.com", svg_text)

    def test_bidirectional_session_continuity_and_locked_skip(self) -> None:
        import sqlite3

        host_ag = self.fake_home / ".gemini" / "antigravity"
        (host_ag / "conversations").mkdir(parents=True)
        (host_ag / "annotations").mkdir(parents=True)
        (host_ag / "chapter_titles").mkdir(parents=True)
        (host_ag / "brain" / "conv-host-1" / ".system_generated" / "logs").mkdir(parents=True)
        (host_ag / "worktrees").mkdir(parents=True)

        ext_wt = Path(self.tmp.name).resolve() / "ext-worktrees" / "repo-a"
        ext_wt.mkdir(parents=True)
        has_wt_symlink = True
        try:
            os.symlink(str(ext_wt), str(host_ag / "worktrees" / "repo-a"))
            # Forbidden symlink pointing inside Host ~/.gemini must NOT be copied.
            forbidden_wt_target = self.fake_home / ".gemini" / "secret-dir"
            forbidden_wt_target.mkdir(parents=True)
            os.symlink(str(forbidden_wt_target), str(host_ag / "worktrees" / "bad-link"))
        except OSError as exc:
            if sys.platform == "win32" and getattr(exc, "winerror", None) == 1314:
                has_wt_symlink = False
            else:
                raise

        # Populate Host conversation_summaries.db + conversations/conv-host-1.db + brain + annotations
        host_sum_db = host_ag / "conversation_summaries.db"
        conn = sqlite3.connect(str(host_sum_db))
        try:
            conn.execute(
                "CREATE TABLE conversation_summaries ("
                "conversation_id TEXT PRIMARY KEY, title TEXT, preview TEXT, "
                "last_modified_time TEXT, workspace_uris TEXT, status TEXT, "
                "project_id TEXT, step_count INTEGER, parent_conversation_id TEXT, raw_summary BLOB)"
            )
            conn.execute(
                "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "conv-host-1",
                    "Main Thread One",
                    "Implementing session sync",
                    "2026-11-16T08:00:00Z",
                    json.dumps(["file:///Volumes/Dev/agy-profiles"]),
                    "IDLE",
                    "proj-main",
                    42,
                    None,
                    b"\x0a\x0fMain Thread One",
                ),
            )
            conn.execute(
                "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "conv-host-locked",
                    "Locked Active Host Thread",
                    "Currently running on Host",
                    "2026-11-16T08:05:00Z",
                    json.dumps(["file:///Volumes/Dev/agy-profiles"]),
                    "RUNNING",
                    "proj-main",
                    10,
                    None,
                    b"\x0a\x19Locked Active Host Thread",
                ),
            )
            conn.execute(
                "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "subagent-child-1",
                    "Subagent Child",
                    "Helper step",
                    "2026-11-16T08:01:00Z",
                    "[]",
                    "DONE",
                    "proj-main",
                    5,
                    "conv-host-1",
                    b"\x0a\x0eSubagent Child",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        for cid_name in ("conv-host-1", "conv-host-locked"):
            c_conn = sqlite3.connect(str(host_ag / "conversations" / "{}.db".format(cid_name)))
            try:
                c_conn.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, body TEXT)")
                c_conn.execute("INSERT INTO steps VALUES (1, ?)", ("hello from {}".format(cid_name),))
                c_conn.commit()
            finally:
                c_conn.close()

        (host_ag / "annotations" / "conv-host-1.pbtxt").write_text('last_user_view_time: "now"\n', encoding="utf-8")
        (host_ag / "chapter_titles" / "conv-host-1.pb").write_bytes(b"\x0a\x05Intro")
        (host_ag / "brain" / "conv-host-1" / "report.md").write_text("# Artifact\n", encoding="utf-8")
        (host_ag / "brain" / "conv-host-1" / ".system_generated" / "logs" / "transcript.jsonl").write_text(
            '{"type":"USER_INPUT","content":"hello"}\n', encoding="utf-8"
        )

        call_tool("profile_create", {"name": "sess-box", "label": "Session Box", "link_policy": "none"}, self.ctx)
        switched = call_tool(
            "profile_switch",
            {"name": "sess-box", "launch": False, "include_sessions": True, "session_limit": 10},
            self.ctx,
        )
        self.assertEqual(switched["sync"]["sessions_synced"], 2)
        self.assertEqual(switched["sync"]["sync_state"]["sessions_count"], 2)

        prof_ag = self.root / "sess-box" / "home" / ".gemini" / "antigravity"
        self.assertTrue((prof_ag / "conversations" / "conv-host-1.db").is_file())
        self.assertFalse((prof_ag / "conversations" / "subagent-child-1.db").exists())
        self.assertTrue((prof_ag / "agyhub_summaries_proto.pb").is_file())
        self.assertIn(b"conv-host-1", (prof_ag / "agyhub_summaries_proto.pb").read_bytes())
        self.assertTrue((prof_ag / "annotations" / "conv-host-1.pbtxt").is_file())
        self.assertTrue((prof_ag / "chapter_titles" / "conv-host-1.pb").is_file())
        self.assertTrue((prof_ag / "brain" / "conv-host-1" / "report.md").is_file())
        if has_wt_symlink:
            self.assertTrue((prof_ag / "worktrees" / "repo-a").is_symlink())
            self.assertFalse((prof_ag / "worktrees" / "bad-link").exists())

        # Simulate backup continuing conv-host-locked AND creating conv-backup-new while Host holds a lock on conv-host-locked
        (host_ag / "presence").mkdir(parents=True, exist_ok=True)
        (host_ag / "presence" / "conv-host-locked.lock").write_text("99999", encoding="utf-8")

        b_sum_conn = sqlite3.connect(str(prof_ag / "conversation_summaries.db"))
        try:
            b_sum_conn.execute(
                "UPDATE conversation_summaries SET step_count = 99, last_modified_time = '2026-11-16T09:00:00Z' "
                "WHERE conversation_id = 'conv-host-locked'"
            )
            b_sum_conn.execute(
                "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "conv-backup-new",
                    "Backup Created Thread",
                    "Continued while quota exhausted",
                    "2026-11-16T09:10:00Z",
                    json.dumps(["file:///Volumes/Dev/agy-profiles"]),
                    "IDLE",
                    "proj-main",
                    18,
                    None,
                    b"\x0a\x15Backup Created Thread",
                ),
            )
            b_sum_conn.commit()
        finally:
            b_sum_conn.close()

        b_new_conn = sqlite3.connect(str(prof_ag / "conversations" / "conv-backup-new.db"))
        try:
            b_new_conn.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, body TEXT)")
            b_new_conn.execute("INSERT INTO steps VALUES (1, 'from backup')")
            b_new_conn.commit()
        finally:
            b_new_conn.close()

        returned = call_tool(
            "profile_switch",
            {"name": "host", "from_source": "sess-box", "launch": False, "include_sessions": True},
            self.ctx,
        )
        self.assertEqual(returned["sessions"]["synced_sessions"], 1)
        self.assertTrue((host_ag / "conversations" / "conv-backup-new.db").is_file())

        # Verify locked Host thread was NOT overwritten by backup's step_count=99
        h_check = sqlite3.connect(str(host_sum_db))
        try:
            locked_steps = h_check.execute(
                "SELECT step_count FROM conversation_summaries WHERE conversation_id = 'conv-host-locked'"
            ).fetchone()[0]
            self.assertEqual(locked_steps, 10)
        finally:
            h_check.close()

    def test_terminal_cli_session_sync_and_resume_runner(self) -> None:
        import sqlite3

        host_cli = self.fake_home / ".gemini" / "antigravity-cli"
        (host_cli / "conversations").mkdir(parents=True)
        (host_cli / "settings.json").write_text(
            json.dumps(
                {
                    "artifactReviewPolicy": "always-proceed",
                    "gateway": {"enabled": True, "url": "https://example.test", "apiKey": "secret-gw-key"},
                }
            ),
            encoding="utf-8",
        )
        cli_sum = host_cli / "conversation_summaries.db"
        conn = sqlite3.connect(str(cli_sum))
        try:
            conn.execute(
                "CREATE TABLE conversation_summaries ("
                "conversation_id TEXT PRIMARY KEY, title TEXT, preview TEXT, "
                "last_modified_time TEXT, workspace_uris TEXT, status TEXT, "
                "project_id TEXT, step_count INTEGER, parent_conversation_id TEXT, raw_summary BLOB)"
            )
            conn.execute(
                "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "cli-conv-1",
                    "Terminal Coding Sprint",
                    "Editing video pipeline",
                    "2026-11-16T09:30:00Z",
                    json.dumps(["file:///Volumes/Dev/ai-video-maker"]),
                    "IDLE",
                    "default-cli-project",
                    55,
                    None,
                    b"\x0a\x16Terminal Coding Sprint",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        c_conn = sqlite3.connect(str(host_cli / "conversations" / "cli-conv-1.db"))
        try:
            c_conn.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, body TEXT)")
            c_conn.execute("INSERT INTO steps VALUES (1, 'terminal coding step')")
            c_conn.commit()
        finally:
            c_conn.close()

        fake_agy = Path(self.tmp.name).resolve() / "fake-agy"
        fake_agy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(str(fake_agy), 0o755)

        call_tool("profile_create", {"name": "term-box", "label": "Term Box", "link_policy": "none"}, self.ctx)
        old_bin_env = os.environ.get("AGY_CLI_BIN")
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            os.environ["AGY_CLI_BIN"] = str(fake_agy)
            sys.stdout = buf
            rc = cli_main(["--root", str(self.root), "resume", "term-box", "--print-env"])
        finally:
            sys.stdout = old_stdout
            if old_bin_env is None:
                os.environ.pop("AGY_CLI_BIN", None)
            else:
                os.environ["AGY_CLI_BIN"] = old_bin_env

        self.assertEqual(rc, 0)
        info = json.loads(buf.getvalue())
        self.assertEqual(info["slot"], "term-box")
        self.assertEqual(
            info["command"],
            [str(fake_agy.resolve()), "-c", "--dangerously-skip-permissions", "--remote-control"],
        )
        self.assertGreaterEqual(info["sessions"]["cli_synced_sessions"], 1)
        self.assertEqual(info["env"]["SSH_CONNECTION"], "local")
        expected_sb_home = str((self.root / "term-box" / "home").resolve())
        self.assertEqual(info["env"]["HOME"], expected_sb_home)

        prof_cli = self.root / "term-box" / "home" / ".gemini" / "antigravity-cli"
        self.assertTrue((prof_cli / "conversations" / "cli-conv-1.db").is_file())
        self.assertTrue((prof_cli / "jetbox_summaries_proto.pb").is_file())
        # Verify CLI thread was also bridged into Hub store so Antigravity Mobile sees terminal chats
        prof_hub = self.root / "term-box" / "home" / ".gemini" / "antigravity"
        self.assertTrue((prof_hub / "conversations" / "cli-conv-1.db").is_file())
        self.assertTrue((prof_hub / "agyhub_summaries_proto.pb").is_file())
        synced_cli_settings = json.loads((prof_cli / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(synced_cli_settings["gateway"]["apiKey"], REDACTED_MARKER)
        self.assertFalse(synced_cli_settings["gateway"]["enabled"])
        self.assertEqual(synced_cli_settings["toolPermission"], "always-proceed")
        self.assertEqual(synced_cli_settings["agentMode"], "auto")
        self.assertFalse(synced_cli_settings["enableTerminalSandbox"])

        prof_cfg = json.loads(
            (self.root / "term-box" / "home" / ".gemini" / "config" / "config.json").read_text(encoding="utf-8")
        )
        self.assertEqual(prof_cfg["userSettings"]["permissionPreset"], "AGENT_PERMISSION_PRESET_TURBO")
        self.assertEqual(prof_cfg["userSettings"]["remotePermissionPreset"], "AGENT_PERMISSION_PRESET_TURBO")
        self.assertTrue(prof_cfg["userSettings"]["remoteControlEnabled"])
        self.assertTrue(prof_cfg["userSettings"]["remoteControlHostname"].endswith("-term-box"))

    def test_auto_failover_watchdog_and_host_cron_pause_restore(self) -> None:
        host_gemini = self.fake_home / ".gemini"
        for sid in ("cron-live", "cron-disabled"):
            sc_dir = host_gemini / "config" / "sidecars" / sid
            sc_dir.mkdir(parents=True)
            (sc_dir / "sidecar.json").write_text(
                json.dumps(
                    {
                        "builtin": "schedule",
                        "display_name": sid,
                        "args": ["0 9 * * *", "echo", sid],
                        "agent_permissions": {"access_grants": ["command(echo)"]},
                    }
                ),
                encoding="utf-8",
            )
        (host_gemini / "config" / "config.json").write_text(
            json.dumps(
                {
                    "sidecars": {
                        "cron-live": {"enabled": True, "schemaVersion": 1},
                        "cron-disabled": {"enabled": False, "schemaVersion": 1},
                    }
                }
            ),
            encoding="utf-8",
        )
        cli_log = host_gemini / "antigravity-cli" / "cli.log"
        cli_log.parent.mkdir(parents=True, exist_ok=True)
        cli_log.write_text("Old historical Quota exhausted line that must be ignored\n", encoding="utf-8")

        call_tool("profile_create", {"name": "backup-auto", "label": "Backup Auto", "link_policy": "none"}, self.ctx)

        # 1. First watchdog poll initializes at EOF and does NOT false-trigger on old logs
        buf1 = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf1
            rc1 = cli_main(["--root", str(self.root), "watchdog", "--once", "--no-launch", "--json"])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc1, 0)
        wd1 = json.loads(buf1.getvalue())
        self.assertTrue(wd1["initialized"])
        self.assertIsNone(wd1["switched_to"])

        # 1b. Per-model 429 ("Individual quota reached") must NEVER false-trigger failover or pause Host automations
        ls_log = self.fake_home / "Library" / "Logs" / "Antigravity" / "language_server.log"
        ls_log.parent.mkdir(parents=True, exist_ok=True)
        ls_log.write_text(
            "E1117 10:43:21 errorreport.go:273] RESOURCE_EXHAUSTED (code 429): Individual quota reached. Resets in 97h.\n",
            encoding="utf-8",
        )
        buf_noise = io.StringIO()
        try:
            sys.stdout = buf_noise
            rc_noise = cli_main(["--root", str(self.root), "watchdog", "--once", "--no-launch", "--json"])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc_noise, 0)
        wd_noise = json.loads(buf_noise.getvalue())
        self.assertFalse(wd_noise["quota_exhausted_detected"])
        self.assertIsNone(wd_noise["switched_to"])

        # 2. Simulate account-wide credit depletion -> watchdog switches to backup, NEVER disables Host cron-live, and enables ONLY cron-live on backup
        with cli_log.open("a", encoding="utf-8") as fh:
            fh.write("E1116 server.go:900] request failed: INSUFFICIENT_G1_CREDITS_BALANCE\n")

        buf2 = io.StringIO()
        try:
            sys.stdout = buf2
            rc2 = cli_main(["--root", str(self.root), "watchdog", "--once", "--no-launch", "--json"])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc2, 0)
        wd2 = json.loads(buf2.getvalue())
        self.assertEqual(wd2["switched_to"], "backup-auto")

        host_cfg_preserved = json.loads((host_gemini / "config" / "config.json").read_text(encoding="utf-8"))
        self.assertTrue(host_cfg_preserved["sidecars"]["cron-live"]["enabled"])
        self.assertFalse(host_cfg_preserved["sidecars"]["cron-disabled"]["enabled"])

        backup_cfg_active = json.loads(
            (self.root / "backup-auto" / "home" / ".gemini" / "config" / "config.json").read_text(encoding="utf-8")
        )
        self.assertTrue(backup_cfg_active["sidecars"]["cron-live"]["enabled"])
        self.assertFalse(backup_cfg_active["sidecars"]["cron-disabled"]["enabled"])

        backup_sc = json.loads(
            (
                self.root / "backup-auto" / "home" / ".gemini" / "config" / "sidecars" / "cron-live" / "sidecar.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIn("command(*)", backup_sc["agent_permissions"]["access_grants"])

        # 3. Return to Host keeps cron-live enabled on Host and pauses backup-auto
        returned = call_tool(
            "profile_switch",
            {"name": "host", "from_source": "backup-auto", "launch": False},
            self.ctx,
        )
        self.assertTrue(returned["switch"]["host_automations_restored"]["host_automations_preserved"])
        host_cfg_restored = json.loads((host_gemini / "config" / "config.json").read_text(encoding="utf-8"))
        self.assertTrue(host_cfg_restored["sidecars"]["cron-live"]["enabled"])
        self.assertFalse(host_cfg_restored["sidecars"]["cron-disabled"]["enabled"])

        # 4. Verify 'agyp auto' terminal wrapper auto-fails over mid-session when Host logs Quota exhausted
        invocations_log = Path(self.tmp.name).resolve() / "invocations.jsonl"
        fake_auto_agy = Path(self.tmp.name).resolve() / "fake-auto-agy"
        fake_auto_agy.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "home = os.environ['HOME']\n"
            "with open({!r}, 'a') as f:\n"
            "    f.write(json.dumps({{'home': home, 'args': sys.argv[1:]}}) + '\\n')\n"
            "if home == {!r}:\n"
            "    with open({!r}, 'a') as lf:\n"
            "        lf.write('Quota exhausted for current account\\n')\n"
            "    sys.exit(1)\n"
            "sys.exit(0)\n".format(
                str(invocations_log),
                str(self.fake_home.resolve()),
                str(cli_log.resolve()),
            ),
            encoding="utf-8",
        )
        os.chmod(str(fake_auto_agy), 0o755)
        old_bin = os.environ.get("AGY_CLI_BIN")
        old_err = sys.stderr
        try:
            os.environ["AGY_CLI_BIN"] = str(fake_auto_agy)
            sys.stderr = io.StringIO()
            rc_auto = cli_main(["--root", str(self.root), "auto", "-p", "finish task"])
        finally:
            sys.stderr = old_err
            if old_bin is None:
                os.environ.pop("AGY_CLI_BIN", None)
            else:
                os.environ["AGY_CLI_BIN"] = old_bin

        self.assertEqual(rc_auto, 0)
        calls = [json.loads(line) for line in invocations_log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["home"], str(self.fake_home.resolve()))
        self.assertIn("--dangerously-skip-permissions", calls[0]["args"])
        self.assertEqual(calls[1]["home"], str((self.root / "backup-auto" / "home").resolve()))
        self.assertIn("-c", calls[1]["args"])
        self.assertIn("--dangerously-skip-permissions", calls[1]["args"])

    def test_host_hub_tls_doctor_and_repair_host(self) -> None:
        host_app_support = self.fake_home / HOST_DATA_DIR_RELPATHS["hub"]
        host_app_support.mkdir(parents=True, exist_ok=True)
        stale_lock = host_app_support / "SingletonLock"
        stale_lock.write_text("stale-host-lock", encoding="utf-8")

        host_logs = self.fake_home / "Library" / "Logs" / "Antigravity"
        host_logs.mkdir(parents=True, exist_ok=True)
        (host_logs / "main.log").write_text(
            "[2026-11-17 12:17:23.065] [info]  Starting app (v2.32.1) with dynamic port\n"
            "[2026-11-17 12:33:15.100] [error] electron: Failed to load URL: https://127.0.0.1:57332/ "
            "with error: ERR_CERT_AUTHORITY_INVALID\n",
            encoding="utf-8",
        )

        repaired = call_tool(
            "profile_repair",
            {"name": "host", "launch": False},
            self.ctx,
        )
        self.assertEqual(repaired["profile"], "host")
        self.assertIn("SingletonLock", repaired["locks_removed"]["hub"])
        self.assertFalse(stale_lock.exists())

    def test_bin_wrapper_execution(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        env = dict(os.environ)
        env["AGY_PROFILES_DIR"] = str(self.root)
        for wrapper in ("agy-profiles", "agyp"):
            proc = subprocess.run(
                [sys.executable, str(repo_root / "bin" / wrapper), "obligations", "--json"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["summary"]["failed"], 0)


if __name__ == "__main__":
    unittest.main()
