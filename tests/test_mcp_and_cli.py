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
from agy_profiles.isolation import REDACTED_MARKER
from agy_profiles.macos_launcher import resolve_launcher_bundle_path, verify_launcher_signature
from agy_profiles.mcp_server import handle_mcp_request, serve_mcp_stdio
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
        self.assertIn("session_recover", tool_names)
        self.assertGreaterEqual(len(tool_names), 18)

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
        os.symlink(str(old_cfg), str(old_link))

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
        self.assertIn("export HOME={}".format(expected_home), zshenv_text)
        self.assertIn("export ZDOTDIR={}".format(expected_home), zshenv_text)

        new_link = new_dir / "home" / ".gemini" / "antigravity" / "mcp_config.json"
        self.assertTrue(new_link.is_symlink())
        self.assertEqual(os.readlink(str(new_link)), str(new_dir / "home" / ".gemini" / "config" / "mcp_config.json"))
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
        self.assertTrue((self.root / "default-box" / "home" / ".agents").is_symlink())
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
        os.symlink(str(ext_wt), str(host_ag / "worktrees" / "repo-a"))

        # Forbidden symlink pointing inside Host ~/.gemini must NOT be copied.
        forbidden_wt_target = self.fake_home / ".gemini" / "secret-dir"
        forbidden_wt_target.mkdir(parents=True)
        os.symlink(str(forbidden_wt_target), str(host_ag / "worktrees" / "bad-link"))

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
        host_app_support = self.fake_home / "Library" / "Application Support" / "Antigravity"
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

    def test_desktop_hub_five_hour_quota_auto_retry_and_bypass(self) -> None:
        from agy_profiles.quota_guard import (
            find_stalled_desktop_conversations,
            parse_quota_summary_buckets,
            poll_desktop_hub_auto_retry,
        )

        # 1. Verify 5-hour quota bucket parsing when Weekly > 0 and 5h == 0 vs 5h > 0
        user_status_resp = {
            "userStatus": {
                "email": "user@example.com",
                "userTier": {"name": "Google AI Pro"},
                "cascadeModelConfigData": {
                    "defaultOverrideModelConfig": {"modelOrAlias": {"model": "MODEL_PLACEHOLDER_M427"}}
                },
            }
        }
        quota_exhausted_5h = {
            "response": {
                "groups": [
                    {
                        "displayName": "Gemini Models",
                        "buckets": [
                            {
                                "bucketId": "gemini-weekly",
                                "displayName": "Weekly Limit Remaining",
                                "window": "weekly",
                                "remainingFraction": 0.52,
                                "resetTime": "2026-11-22T05:00:00Z",
                            },
                            {
                                "bucketId": "gemini-5h",
                                "displayName": "Five Hour Limit Remaining",
                                "window": "5h",
                                "remainingFraction": 0.0,
                                "resetTime": "2026-11-17T14:00:00Z",
                            },
                        ],
                    }
                ]
            }
        }
        parsed_paused = parse_quota_summary_buckets(quota_exhausted_5h, user_status_resp)
        self.assertTrue(parsed_paused["five_hour_exhausted_while_weekly_available"])
        self.assertFalse(parsed_paused["weekly_exhausted"])
        self.assertFalse(parsed_paused["can_dispatch_now"])

        quota_exhausted_weekly = {
            "response": {
                "groups": [
                    {
                        "displayName": "Gemini Models",
                        "buckets": [
                            {
                                "bucketId": "gemini-weekly",
                                "displayName": "Weekly Limit Remaining",
                                "window": "weekly",
                                "remainingFraction": 0.0,
                                "resetTime": "2026-11-22T05:00:00Z",
                            },
                            {
                                "bucketId": "gemini-5h",
                                "displayName": "Five Hour Limit Remaining",
                                "window": "5h",
                                "remainingFraction": 1.0,
                                "resetTime": "2026-11-17T14:00:00Z",
                            },
                        ],
                    }
                ]
            }
        }
        parsed_weekly = parse_quota_summary_buckets(quota_exhausted_weekly, user_status_resp)
        self.assertTrue(parsed_weekly["weekly_exhausted"])
        self.assertFalse(parsed_weekly["can_dispatch_now"])

        # When Argon bucket still has balance, dispatch switches to MODEL_PLACEHOLDER_M417 immediately
        quota_with_argon = {
            "response": {
                "groups": [
                    quota_exhausted_5h["response"]["groups"][0],
                    {
                        "displayName": "Gemini 4 Argon",
                        "buckets": [
                            {
                                "bucketId": "gemini-argon-wtu-weekly",
                                "displayName": "Gemini 4 Argon Weekly Limit",
                                "window": "weekly",
                                "remainingFraction": 0.85,
                                "resetTime": "2026-11-22T05:00:00Z",
                            }
                        ],
                    },
                ]
            }
        }
        parsed_argon = parse_quota_summary_buckets(quota_with_argon, user_status_resp)
        self.assertTrue(parsed_argon["can_dispatch_now"])
        self.assertEqual(parsed_argon["preferred_plan_model"], "MODEL_PLACEHOLDER_M417")

        # 2. Create transcripts for (a) completed conversation, (b) user-canceled conversation,
        # (c) healthy swarm_wait conversation, (d) stalled 5h quota swarm coordinator, (e) stalled stream timeout
        brain_dir = self.fake_home / ".gemini" / "antigravity" / "brain"
        def _write_transcript(cid: str, lines: list[dict]) -> None:
            t_dir = brain_dir / cid / ".system_generated" / "logs"
            t_dir.mkdir(parents=True, exist_ok=True)
            (t_dir / "transcript.jsonl").write_text(
                "\n".join(json.dumps(x) for x in lines) + "\n",
                encoding="utf-8",
            )

        _write_transcript(
            "conv-done",
            [{"step_index": 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "status": "DONE", "content": "All done."}],
        )
        _write_transcript(
            "conv-canceled",
            [{"step_index": 1, "source": "SYSTEM", "type": "ERROR_MESSAGE", "status": "DONE", "error": "Canceled"}],
        )
        _write_transcript(
            "conv-swarm-waiting",
            [
                {
                    "step_index": 10,
                    "source": "MODEL",
                    "type": "GENERIC",
                    "status": "DONE",
                    "content": "Waiting for a message that calls on you by name, or on @all posted after #117.",
                }
            ],
        )
        _write_transcript(
            "conv-quota-stalled",
            [
                {
                    "step_index": 12,
                    "source": "SYSTEM",
                    "type": "SYSTEM_MESSAGE",
                    "status": "DONE",
                    "content": "The subagent worker encountered an error: RESOURCE_EXHAUSTED (code 429): Individual quota reached. Resets in 2h.",
                },
                {
                    "step_index": 13,
                    "source": "SYSTEM_SDK",
                    "type": "SYSTEM_MESSAGE",
                    "status": "DONE",
                    "content": "PreInvocation hook",
                },
            ],
        )
        _write_transcript(
            "conv-stream-timeout",
            [
                {
                    "step_index": 5,
                    "source": "SYSTEM",
                    "type": "ERROR_MESSAGE",
                    "status": "DONE",
                    "error": "API error (attempt 1): request failed: stream idle timeout (5m0s): context deadline exceeded",
                }
            ],
        )

        summaries = {
            "conv-done": {
                "summary": "Finished Task",
                "status": "CASCADE_RUN_STATUS_IDLE",
                "stepCount": 2,
                "lastModifiedTime": "2026-11-17T10:00:00Z",
                "latestExecutorTerminationReason": "EXECUTOR_TERMINATION_REASON_NO_TOOL_CALL",
            },
            "conv-canceled": {
                "summary": "Canceled Task",
                "status": "CASCADE_RUN_STATUS_IDLE",
                "stepCount": 2,
                "lastModifiedTime": "2026-11-17T10:00:00Z",
                "latestExecutorTerminationReason": "EXECUTOR_TERMINATION_REASON_USER_CANCELED",
            },
            "conv-swarm-waiting": {
                "summary": "Swarm Waiting",
                "status": "CASCADE_RUN_STATUS_IDLE",
                "stepCount": 11,
                "lastModifiedTime": "2026-11-17T10:00:00Z",
                "latestExecutorTerminationReason": "EXECUTOR_TERMINATION_REASON_TERMINAL_CUSTOM_HOOK",
            },
            "conv-quota-stalled": {
                "summary": "Overnight Swarm Coordinator",
                "status": "CASCADE_RUN_STATUS_IDLE",
                "stepCount": 14,
                "lastModifiedTime": "2026-11-17T10:05:00Z",
                "latestExecutorTerminationReason": "EXECUTOR_TERMINATION_REASON_TERMINAL_CUSTOM_HOOK",
            },
            "conv-stream-timeout": {
                "summary": "Overnight Feature Build",
                "status": "CASCADE_RUN_STATUS_IDLE",
                "stepCount": 6,
                "lastModifiedTime": "2026-11-17T10:04:00Z",
                "latestExecutorTerminationReason": "EXECUTOR_TERMINATION_REASON_ERROR",
            },
        }

        now_epoch = 1794910200.0  # 2026-11-17T10:10:00Z
        stalled = find_stalled_desktop_conversations(summaries, brain_dir, now_epoch=now_epoch)
        self.assertEqual([c["cascade_id"] for c in stalled], ["conv-quota-stalled", "conv-stream-timeout"])
        self.assertTrue(stalled[0]["needs_prompt_bypass"])
        self.assertFalse(stalled[1]["needs_prompt_bypass"])

        # 3. Verify poll_desktop_hub_auto_retry dispatches SendUserCascadeMessage once 5h quota refreshes
        quota_refreshed_5h = {
            "response": {
                "groups": [
                    {
                        "displayName": "Gemini Models",
                        "buckets": [
                            {
                                "bucketId": "gemini-weekly",
                                "displayName": "Weekly Limit Remaining",
                                "window": "weekly",
                                "remainingFraction": 0.52,
                                "resetTime": "2026-11-22T05:00:00Z",
                            },
                            {
                                "bucketId": "gemini-5h",
                                "displayName": "Five Hour Limit Remaining",
                                "window": "5h",
                                "remainingFraction": 0.29,
                                "resetTime": "2026-11-17T14:00:00Z",
                            },
                        ],
                    }
                ]
            }
        }
        sent_rpcs: list[tuple[int, str, str, dict]] = []

        def _fake_rpc(port: int, token: str, method: str, body: dict | None = None) -> dict:
            if method == "GetUserStatus":
                return user_status_resp
            if method == "RetrieveUserQuotaSummary":
                return quota_refreshed_5h
            if method == "GetAllCascadeTrajectories":
                return {"trajectorySummaries": summaries}
            if method == "SendUserCascadeMessage":
                sent_rpcs.append((port, token, method, body or {}))
                return {}
            return {}

        fake_ps = [
            {
                "pid": 2001,
                "ppid": 1,
                "pgid": 2001,
                "command": "/Applications/Antigravity.app/Contents/MacOS/Antigravity",
            },
            {
                "pid": 2002,
                "ppid": 2001,
                "pgid": 2001,
                "command": "/Applications/Antigravity.app/Contents/Resources/bin/language_server --standalone --subclient_type hub --csrf_token tok-host-123",
            },
        ]

        from unittest import mock
        with mock.patch("agy_profiles.quota_guard._resolve_port_from_devtools_file", return_value=50368):
            report1, ledger1 = poll_desktop_hub_auto_retry(
                self.ctx,
                ledger={},
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=now_epoch,
            )
            self.assertEqual(report1["resumed_total"], 2)
            self.assertEqual(len(sent_rpcs), 2)
            # First stalled conversation (quota_pause custom hook) receives continuation prompt
            self.assertEqual(sent_rpcs[0][3]["cascadeId"], "conv-quota-stalled")
            self.assertEqual(len(sent_rpcs[0][3]["items"]), 1)
            # Second stalled conversation (stream timeout error) receives empty retry payload first
            self.assertEqual(sent_rpcs[1][3]["cascadeId"], "conv-stream-timeout")
            self.assertEqual(sent_rpcs[1][3]["items"], [])

            # Immediate re-poll within cooldown does not duplicate SendUserCascadeMessage
            report2, _ = poll_desktop_hub_auto_retry(
                self.ctx,
                ledger=ledger1,
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=now_epoch + 10.0,
            )
            self.assertEqual(report2["resumed_total"], 0)
            self.assertEqual(len(sent_rpcs), 2)

    def test_rpc_hidden_executor_error_recovery_and_auth_reset(self) -> None:
        from unittest import mock

        from agy_profiles.quota_guard import (
            MAX_ATTEMPTS_PER_STALL,
            parse_quota_summary_buckets,
            poll_desktop_hub_auto_retry,
            recover_desktop_sessions_once,
        )

        brain_dir = self.fake_home / ".gemini" / "antigravity" / "brain"

        def _write_transcript(cid: str, lines: list[dict]) -> None:
            t_dir = brain_dir / cid / ".system_generated" / "logs"
            t_dir.mkdir(parents=True, exist_ok=True)
            (t_dir / "transcript.jsonl").write_text(
                "\n".join(json.dumps(x) for x in lines) + "\n",
                encoding="utf-8",
            )

        conv_main = "6b29f77a-c6b2-4d37-91d5-e85985f45998"
        conv_missing_model = "424ed305-485d-4729-9193-44dc7e74dd4e"

        _write_transcript(
            conv_main,
            [
                {
                    "step_index": 7638,
                    "source": "MODEL",
                    "type": "PLANNER_RESPONSE",
                    "status": "DONE",
                    "content": "Hold flat.",
                }
            ],
        )
        _write_transcript(
            conv_missing_model,
            [
                {
                    "step_index": 2600,
                    "source": "MODEL",
                    "type": "PLANNER_RESPONSE",
                    "status": "DONE",
                    "content": "Ready.",
                }
            ],
        )

        summaries = {
            conv_main: {
                "summary": "Trading Hub",
                "status": "CASCADE_RUN_STATUS_IDLE",
                "stepCount": 7640,
                "lastModifiedTime": "2026-11-20T04:45:42Z",
                "latestExecutorTerminationReason": "EXECUTOR_TERMINATION_REASON_NO_TOOL_CALL",
            },
            conv_missing_model: {
                "summary": "Backup Hub",
                "status": "CASCADE_RUN_STATUS_IDLE",
                "stepCount": 2602,
                "lastModifiedTime": "2026-11-20T04:45:40Z",
                "latestExecutorTerminationReason": "EXECUTOR_TERMINATION_REASON_NO_TOOL_CALL",
            },
        }

        quota_ok = {
            "response": {
                "groups": [
                    {
                        "displayName": "Gemini Models",
                        "buckets": [
                            {
                                "bucketId": "gemini-weekly",
                                "displayName": "Weekly Limit Remaining",
                                "window": "weekly",
                                "remainingFraction": 0.25,
                                "resetTime": "2026-11-22T05:00:00Z",
                            },
                            {
                                "bucketId": "gemini-5h",
                                "displayName": "Five Hour Limit Remaining",
                                "window": "5h",
                                "remainingFraction": 1.0,
                                "resetTime": "2026-11-20T09:45:00Z",
                            },
                        ],
                    }
                ]
            }
        }

        # 1. Mid-login window: clientModelConfigs is empty -> models_loaded False -> 0 dispatches
        mid_login_status = {
            "userStatus": {
                "email": "old@example.com",
                "cascadeModelConfigData": {
                    "defaultOverrideModelConfig": {"modelOrAlias": {"model": "MODEL_PLACEHOLDER_M532"}},
                    "clientModelConfigs": [],
                },
            }
        }
        parsed_mid = parse_quota_summary_buckets(quota_ok, mid_login_status)
        self.assertFalse(parsed_mid["models_loaded"])
        self.assertFalse(parsed_mid["can_dispatch_now"])

        # Put Opus M26 first to ensure fallback never selects unavailable/disallowed Opus M26.
        ready_status = {
            "userStatus": {
                "email": "old@example.com",
                "cascadeModelConfigData": {
                    "defaultOverrideModelConfig": {"modelOrAlias": {"model": "MODEL_PLACEHOLDER_M669"}},
                    "clientModelConfigs": [
                        {
                            "label": "Claude Opus 4.6",
                            "modelOrAlias": {"model": "MODEL_PLACEHOLDER_M26"},
                            "quotaInfo": {"remainingFraction": 0.9},
                        },
                        {
                            "label": "Gemini 4 Neon (High)",
                            "modelOrAlias": {"model": "MODEL_PLACEHOLDER_M532"},
                            "quotaInfo": {"remainingFraction": 0.25},
                        },
                    ],
                },
            }
        }
        parsed_ready = parse_quota_summary_buckets(quota_ok, ready_status)
        self.assertTrue(parsed_ready["models_loaded"])
        self.assertTrue(parsed_ready["can_dispatch_now"])
        self.assertEqual(parsed_ready["preferred_plan_model"], "MODEL_PLACEHOLDER_M532")

        fake_ps = [
            {
                "pid": 3001,
                "ppid": 1,
                "pgid": 3001,
                "command": "/Applications/Antigravity.app/Contents/MacOS/Antigravity",
            },
            {
                "pid": 3002,
                "ppid": 3001,
                "pgid": 3001,
                "command": "/Applications/Antigravity.app/Contents/Resources/bin/language_server --standalone --subclient_type hub --csrf_token tok-host-999",
            },
        ]

        state_box = {"user_status": mid_login_status}
        sent_rpcs: list[dict] = []

        def _fake_rpc(_port: int, _token: str, method: str, body: dict | None = None) -> dict:
            if method == "GetUserStatus":
                return state_box["user_status"]
            if method == "RetrieveUserQuotaSummary":
                return quota_ok
            if method == "GetAllCascadeTrajectories":
                return {"trajectorySummaries": summaries}
            if method == "GetCascadeTrajectorySteps":
                cid = (body or {}).get("cascadeId")
                if cid == conv_main:
                    return {
                        "steps": [
                            {
                                "type": "CORTEX_STEP_TYPE_PLANNER_RESPONSE",
                                "status": "CORTEX_STEP_STATUS_DONE",
                                "metadata": {
                                    "generatorModel": "MODEL_PLACEHOLDER_M532",
                                    "sourceTrajectoryStepInfo": {"stepIndex": 7638},
                                },
                            },
                            {
                                "type": "CORTEX_STEP_TYPE_ERROR_MESSAGE",
                                "status": "CORTEX_STEP_STATUS_DONE",
                                "errorMessage": {
                                    "error": {
                                        "userErrorMessage": "Agent execution terminated due to error.",
                                        "shortError": "failed to construct executor: unknown model key MODEL_PLACEHOLDER_M532: model not found",
                                    }
                                },
                            },
                        ]
                    }
                if cid == conv_missing_model:
                    return {
                        "steps": [
                            {
                                "type": "CORTEX_STEP_TYPE_PLANNER_RESPONSE",
                                "status": "CORTEX_STEP_STATUS_DONE",
                                "metadata": {
                                    "generatorModel": "MODEL_PLACEHOLDER_M669",
                                    "sourceTrajectoryStepInfo": {"stepIndex": 2600},
                                },
                            },
                            {
                                "type": "CORTEX_STEP_TYPE_ERROR_MESSAGE",
                                "status": "CORTEX_STEP_STATUS_DONE",
                                "errorMessage": {
                                    "error": {
                                        "shortError": "failed to construct executor: unknown model key MODEL_PLACEHOLDER_M669: model not found",
                                    }
                                },
                            },
                        ]
                    }
            if method == "SendUserCascadeMessage":
                sent_rpcs.append(body or {})
                return {}
            return {}

        now_epoch = 1795150000.0  # 2026-11-20T04:46:40Z (58s after crash)
        with mock.patch("agy_profiles.quota_guard._resolve_port_from_devtools_file", return_value=50368):
            rep_mid, ledger = poll_desktop_hub_auto_retry(
                self.ctx,
                ledger={},
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=now_epoch,
            )
            self.assertEqual(rep_mid["stalled_total"], 2)
            self.assertEqual(rep_mid["resumed_total"], 0)

            # 2. Models finish loading -> auth transition triggers immediate recovery with continuation prompt
            state_box["user_status"] = ready_status
            rep_ready, ledger = poll_desktop_hub_auto_retry(
                self.ctx,
                ledger=ledger,
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=now_epoch + 5.0,
            )
            self.assertEqual(rep_ready["resumed_total"], 2)
            self.assertTrue(rep_ready["hubs_inspected"][0]["auth_refreshed"])
            self.assertEqual(len(sent_rpcs), 2)
            for payload in sent_rpcs:
                self.assertEqual(len(payload["items"]), 1)
                self.assertIn("/schedule timers", payload["items"][0]["text"])
                self.assertEqual(payload["cascadeConfig"]["plannerConfig"]["planModel"], "MODEL_PLACEHOLDER_M532")

            # 3. Anti-retry-storm: bumping stepCount without advancing last_good_step within 300s is skipped
            summaries[conv_main]["stepCount"] = 7642
            rep_storm, ledger = poll_desktop_hub_auto_retry(
                self.ctx,
                ledger=ledger,
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=now_epoch + 65.0,
            )
            self.assertEqual(rep_storm["resumed_total"], 0)
            self.assertEqual(len(sent_rpcs), 2)

            # 4. After 300s cooldown, attempt 2 fires; up to MAX_ATTEMPTS_PER_STALL (5)
            t_cur = now_epoch + 5.0
            for expected_attempt in range(2, MAX_ATTEMPTS_PER_STALL + 1):
                t_cur += 305.0
                rep_retry, ledger = poll_desktop_hub_auto_retry(
                    self.ctx,
                    ledger=ledger,
                    ps_rows=fake_ps,
                    rpc_caller=_fake_rpc,
                    now_epoch=t_cur,
                )
                self.assertEqual(rep_retry["resumed_total"], 2)
                self.assertEqual(rep_retry["resumed_conversations"][0]["attempt"], expected_attempt)

            # Attempt 6 is blocked by MAX_ATTEMPTS_PER_STALL
            rep_capped, ledger = poll_desktop_hub_auto_retry(
                self.ctx,
                ledger=ledger,
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=t_cur + 305.0,
            )
            self.assertEqual(rep_capped["resumed_total"], 0)

            # 5. Auth change (user logged out and signed into new@example.com) resets ledger and resumes immediately
            new_acct_status = json.loads(json.dumps(ready_status))
            new_acct_status["userStatus"]["email"] = "new@example.com"
            state_box["user_status"] = new_acct_status
            rep_relogin, ledger = poll_desktop_hub_auto_retry(
                self.ctx,
                ledger=ledger,
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=t_cur + 310.0,
            )
            self.assertTrue(rep_relogin["hubs_inspected"][0]["auth_refreshed"])
            self.assertEqual(rep_relogin["resumed_total"], 2)
            self.assertEqual(rep_relogin["resumed_conversations"][0]["attempt"], 1)

            # 6. Verify causal RCA incident_stories, hash-chained audit receipts, dry_run + CLI/MCP path
            stories = {s["root_cause_class"]: s for s in rep_relogin.get("incident_stories") or []}
            self.assertIn("AUTH_LOGIN_MODEL_GAP", stories)
            self.assertIn("ACCOUNT_MODEL_MISSING", stories)
            self.assertEqual(stories["AUTH_LOGIN_MODEL_GAP"]["affected_count"], 1)
            self.assertEqual(stories["ACCOUNT_MODEL_MISSING"]["resumed_count"], 1)

            rep_dry = recover_desktop_sessions_once(
                self.ctx,
                dry_run=True,
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=t_cur + 315.0,
            )
            self.assertTrue(rep_dry["dry_run"])
            self.assertEqual(rep_dry["stalled_total"], 2)
            self.assertEqual(rep_dry["resumed_total"], 0)
            audit_file = self.root / "logs" / "recovery-audit.jsonl"
            self.assertFalse(audit_file.exists())

            rep_live_1 = recover_desktop_sessions_once(
                self.ctx,
                dry_run=False,
                reset_ledger=True,
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=t_cur + 320.0,
            )
            self.assertEqual(rep_live_1["resumed_total"], 2)
            self.assertTrue(rep_live_1.get("audit_receipt_hash"))

            rep_live_2 = recover_desktop_sessions_once(
                self.ctx,
                dry_run=False,
                reset_ledger=True,
                ps_rows=fake_ps,
                rpc_caller=_fake_rpc,
                now_epoch=t_cur + 325.0,
            )
            self.assertEqual(rep_live_2["resumed_total"], 2)
            self.assertTrue(audit_file.is_file())
            receipt_lines = [
                json.loads(line)
                for line in audit_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(receipt_lines), 2)
            self.assertEqual(receipt_lines[0]["prev_hash"], "GENESIS")
            self.assertEqual(receipt_lines[1]["prev_hash"], receipt_lines[0]["receipt_hash"])
            raw_audit = audit_file.read_text(encoding="utf-8")
            self.assertNotIn("new@example.com", raw_audit)
            self.assertNotIn("tok-host-999", raw_audit)

        mcp_res = call_tool("session_recover", {"scope": "all", "dry_run": True}, self.ctx)
        self.assertIn("evidence", mcp_res)
        self.assertTrue(mcp_res["dry_run"])

        buf_rec = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf_rec
            rc_rec = cli_main(["--root", str(self.root), "recover", "--dry-run", "--json"])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(rc_rec, 0)
        cli_rec = json.loads(buf_rec.getvalue())
        self.assertTrue(cli_rec["dry_run"])
        self.assertIn("stalled_total", cli_rec)

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

    def test_transcript_fallback_email_switch_and_503_agentapi_recovery(self) -> None:
        from agy_profiles.quota_guard import (
            MODEL_CAPACITY_CONTINUATION_PROMPT,
            PENDING_HUB_RECOVERY_FILENAME,
            recover_desktop_sessions_once,
        )

        app_dir = self.fake_home / "Library" / "Application Support" / "Antigravity"
        app_dir.mkdir(parents=True, exist_ok=True)
        (app_dir / "app_storage.json").write_text(
            json.dumps({"agy.onboarding.lastLoginUsername": "new@gmail.com"}),
            encoding="utf-8",
        )

        brain_dir = self.fake_home / ".gemini" / "antigravity" / "brain"
        root_cid = "11111111-1111-4111-8111-111111111111"
        sub_cid = "22222222-2222-4222-8222-222222222222"

        root_log = brain_dir / root_cid / ".system_generated" / "logs" / "transcript.jsonl"
        root_log.parent.mkdir(parents=True, exist_ok=True)
        root_log.write_text(
            "\n".join(
                [
                    json.dumps({"step_index": 1, "type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "<USER_REQUEST>ship prod fix</USER_REQUEST>"}),
                    json.dumps({"step_index": 2, "type": "PLANNER_RESPONSE", "source": "MODEL", "status": "DONE", "content": "working"}),
                    json.dumps({"step_index": 3, "type": "ERROR_MESSAGE", "source": "SYSTEM", "error": "API error (attempt 8): UNAVAILABLE (code 503): No capacity available for model gemini-4-hydrogen-xhigh"}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        sub_log = brain_dir / sub_cid / ".system_generated" / "logs" / "transcript.jsonl"
        sub_log.parent.mkdir(parents=True, exist_ok=True)
        sub_log.write_text(
            "\n".join(
                [
                    json.dumps({"step_index": 1, "type": "USER_INPUT", "source": "USER", "content": "Subagent task"}),
                    json.dumps({"step_index": 2, "type": "ERROR_MESSAGE", "source": "SYSTEM", "error": "RESOURCE_EXHAUSTED (code 429)"}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        old_ts = 1_795_400_000.0
        for p in (root_log, sub_log):
            os.utime(str(p), (old_ts, old_ts))

        # Seed prior ledger under old email and exhausted attempt cap so email switch resets it.
        (self.root / ".quota-watchdog.json").write_text(
            json.dumps(
                {
                    "desktop_retry_ledger": {
                        "__auth_state__": {"host": {"email": "old@gmail.com", "signed_in": True, "can_dispatch_now": True}},
                        f"host:{root_cid}": {"attempts": 5, "updated_at_epoch": old_ts, "last_good_step": 2},
                    }
                }
            ),
            encoding="utf-8",
        )

        def _fake_probe(_home: Path) -> dict:
            return {
                "models_loaded": True,
                "available_models": {"gemini-pro-orchestrator": None, "gemini-4-carbon-high": None},
                "preferred_plan_model": "gemini-pro-orchestrator",
            }

        def _meta_check(cid: str):
            return cid == root_cid

        dry = recover_desktop_sessions_once(
            self.ctx,
            dry_run=True,
            ps_rows=[],
            now_epoch=old_ts + 60.0,
            transcript_fallback=True,
            cli_models_probe=_fake_probe,
            metadata_checker=_meta_check,
        )
        self.assertTrue(dry["hubs_inspected"][0]["auth_refreshed"])
        self.assertEqual(dry["hubs_inspected"][0]["email"], "new@gmail.com")
        self.assertEqual(dry["stalled_total"], 1)
        self.assertEqual(dry["incident_stories"][0]["root_cause_class"], "MODEL_CAPACITY_503")
        self.assertEqual(dry["resumed_total"], 0)

        # Without ANTIGRAVITY_LS_ADDRESS / agentapi_sender, host desktop threads are queued cleanly.
        old_ls = os.environ.pop("ANTIGRAVITY_LS_ADDRESS", None)
        try:
            queued_res = recover_desktop_sessions_once(
                self.ctx,
                dry_run=False,
                ps_rows=[],
                now_epoch=old_ts + 65.0,
                transcript_fallback=True,
                cli_models_probe=_fake_probe,
                metadata_checker=_meta_check,
            )
            self.assertEqual(queued_res["resumed_total"], 0)
            pending_doc = json.loads((self.root / PENDING_HUB_RECOVERY_FILENAME).read_text(encoding="utf-8"))
            self.assertIn(root_cid, pending_doc)
        finally:
            if old_ls is not None:
                os.environ["ANTIGRAVITY_LS_ADDRESS"] = old_ls

        # Now switch to a second new email with agentapi sender -> ledger resets and dispatches immediately.
        (app_dir / "app_storage.json").write_text(
            json.dumps({"agy.onboarding.lastLoginUsername": "third@gmail.com"}),
            encoding="utf-8",
        )
        sent: list[tuple[str, str]] = []
        live_res = recover_desktop_sessions_once(
            self.ctx,
            dry_run=False,
            ps_rows=[],
            now_epoch=old_ts + 120.0,
            transcript_fallback=True,
            cli_models_probe=_fake_probe,
            metadata_checker=_meta_check,
            agentapi_sender=lambda cid, text: sent.append((cid, text)) or {"ok": True},
        )
        self.assertEqual(live_res["resumed_total"], 1)
        self.assertEqual(sent[0][0], root_cid)
        self.assertEqual(sent[0][1], MODEL_CAPACITY_CONTINUATION_PROMPT)
        self.assertEqual(live_res["resumed_conversations"][0]["mode"], "agentapi_send_message")
        pending_after = json.loads((self.root / PENDING_HUB_RECOVERY_FILENAME).read_text(encoding="utf-8"))
        self.assertNotIn(root_cid, pending_after)

    def test_recovery_hook_stop_capacity_and_session_start(self) -> None:
        import importlib.util

        repo_root = Path(__file__).resolve().parents[1]
        hook_path = repo_root / "antigravity-plugin" / "hooks" / "agy-recovery-hook.py"
        spec = importlib.util.spec_from_file_location("agy_recovery_hook", str(hook_path))
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        cid = "33333333-3333-4333-8333-333333333333"
        old_no_spawn = os.environ.get("AGY_HOOK_NO_SPAWN")
        os.environ["AGY_HOOK_NO_SPAWN"] = "1"
        try:
            # Allow path: Stop on 503 capacity error auto-continues up to 2 times.
            res1 = mod.handle_hook_event(
                {
                    "conversationId": cid,
                    "terminationReason": "ERROR",
                    "error": "UNAVAILABLE (code 503): No capacity available",
                    "continuationActive": False,
                },
                event="Stop",
                root_dir=self.root,
                home_dir=self.fake_home,
                now_ts=1_795_400_000.0,
            )
            self.assertEqual(res1.get("decision"), "continue")
            queue_doc = json.loads((self.root / ".stalled-queue.json").read_text(encoding="utf-8"))
            self.assertIn(cid, queue_doc)

            # Anti-loop block 1: continuationActive=True must stop cleanly.
            res_loop = mod.handle_hook_event(
                {
                    "conversationId": cid,
                    "terminationReason": "ERROR",
                    "error": "UNAVAILABLE (code 503): No capacity available",
                    "continuationActive": True,
                },
                event="Stop",
                root_dir=self.root,
                home_dir=self.fake_home,
                now_ts=1_795_400_010.0,
            )
            self.assertEqual(res_loop, {})

            # Second retry succeeds; 3rd inside 600s is capped to prevent runaway loop.
            res2 = mod.handle_hook_event(
                {
                    "conversationId": cid,
                    "terminationReason": "ERROR",
                    "error": "UNAVAILABLE (code 503): No capacity available",
                    "continuationActive": False,
                },
                event="Stop",
                root_dir=self.root,
                home_dir=self.fake_home,
                now_ts=1_795_400_020.0,
            )
            self.assertEqual(res2.get("decision"), "continue")
            res3 = mod.handle_hook_event(
                {
                    "conversationId": cid,
                    "terminationReason": "ERROR",
                    "error": "UNAVAILABLE (code 503): No capacity available",
                    "continuationActive": False,
                },
                event="Stop",
                root_dir=self.root,
                home_dir=self.fake_home,
                now_ts=1_795_400_030.0,
            )
            self.assertEqual(res3, {})

            # USER_CANCELED and quota 429 must never trigger Stop-hook infinite loop.
            self.assertEqual(
                mod.handle_hook_event(
                    {"conversationId": "4444", "terminationReason": "USER_CANCELED"},
                    event="Stop",
                    root_dir=self.root,
                    home_dir=self.fake_home,
                    now_ts=1_795_400_040.0,
                ),
                {},
            )
            self.assertEqual(
                mod.handle_hook_event(
                    {"conversationId": "5555", "terminationReason": "ERROR", "error": "RESOURCE_EXHAUSTED (code 429)"},
                    event="Stop",
                    root_dir=self.root,
                    home_dir=self.fake_home,
                    now_ts=1_795_400_050.0,
                ),
                {},
            )

            # SessionStart returns {} cleanly even with email change + queued items.
            app_dir = self.fake_home / "Library" / "Application Support" / "Antigravity"
            app_dir.mkdir(parents=True, exist_ok=True)
            (app_dir / "app_storage.json").write_text(
                json.dumps({"agy.onboarding.lastLoginUsername": "fresh@gmail.com"}),
                encoding="utf-8",
            )
            sess_res = mod.handle_hook_event(
                {"conversationId": cid},
                event="SessionStart",
                root_dir=self.root,
                home_dir=self.fake_home,
                now_ts=1_795_400_060.0,
            )
            self.assertEqual(sess_res, {})
        finally:
            if old_no_spawn is None:
                os.environ.pop("AGY_HOOK_NO_SPAWN", None)
            else:
                os.environ["AGY_HOOK_NO_SPAWN"] = old_no_spawn


if __name__ == "__main__":
    unittest.main()
