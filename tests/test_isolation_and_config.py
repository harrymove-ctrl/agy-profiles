"""Tests for config validation, containment, permissions, and fail-closed secret scrubbing."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agy_profiles.config import (
    ProfileManifest,
    TargetInfo,
    ensure_symlink_slot_within_root,
    ensure_within_root,
    load_manifest,
    resolve_profiles_root,
    save_manifest,
    validate_profile_name,
)
import base64
import sqlite3

from agy_profiles.errors import ToolError
from agy_profiles.isolation import (
    HANDOFF_START_MARKER,
    REDACTED_MARKER,
    audit_profile_isolation,
    create_safe_link,
    collect_host_handoff,
    detect_host_account,
    detect_profile_account,
    inherit_host_customizations,
    provision_profile_dirs,
    purge_stale_caches_if_upgraded,
    sanitize_mcp_json_text,
    sync_host_customizations,
    validate_link_relpath,
    write_handoff_context,
)
from agy_profiles.tools import RuntimeContext, call_tool


class ConfigAndIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "profiles"
        self.root.mkdir(mode=0o700)
        self.fake_home = self.base / "fake-host-home"
        self.fake_home.mkdir(mode=0o700)
        (self.fake_home / ".local" / "bin").mkdir(parents=True)
        (self.fake_home / ".cargo" / "bin").mkdir(parents=True)
        (self.fake_home / ".ssh").mkdir()
        (self.fake_home / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_profile_name_validation_and_reserved_rejection(self) -> None:
        self.assertEqual(validate_profile_name("core-research"), "core-research")
        self.assertEqual(validate_profile_name("team.alpha_1"), "team.alpha_1")
        for bad in ["", "../etc", "a..b", "default", "ALL", "a/b", "bad name", "-leading", "x" * 49]:
            with self.assertRaises(ToolError):
                validate_profile_name(bad)

    def test_containment_blocks_symlink_escape(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        escape_link = self.root / "escape"
        create_safe_link(outside, escape_link)

        with self.assertRaises(ToolError):
            ensure_within_root(self.root, escape_link / "secret.json")

        # Removing or replacing the symlink slot directly inside root is allowed.
        slot = ensure_symlink_slot_within_root(self.root, escape_link)
        self.assertEqual(slot, self.root / "escape")

    def test_provision_sets_strict_modes_and_zshenv_home(self) -> None:
        manifest = ProfileManifest(
            schema_version=1,
            name="work",
            label="Work",
            accent="#3B82F6",
            default_target="hub",
            link_policy="minimal",
            auth_mode="isolated-file",
        )
        provision_profile_dirs(self.root, manifest, real_home=self.fake_home)
        pdir = self.root / "work"
        save_manifest(self.root, pdir, manifest)

        if sys.platform != "win32":
            self.assertEqual(pdir.stat().st_mode & 0o777, 0o700)
            self.assertEqual((pdir / "home").stat().st_mode & 0o777, 0o700)
            self.assertEqual((pdir / "data").stat().st_mode & 0o777, 0o700)
            self.assertEqual((pdir / "ide-data").stat().st_mode & 0o777, 0o700)
            self.assertEqual((pdir / "profile.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((pdir / "home" / ".zshenv").stat().st_mode & 0o777, 0o600)

        zshenv = (pdir / "home" / ".zshenv").read_text(encoding="utf-8")
        self.assertIn("export HOME=", zshenv)
        self.assertIn(str((pdir / "home").resolve()), zshenv)

        app_storage = json.loads((pdir / "data" / "app_storage.json").read_text(encoding="utf-8"))
        self.assertEqual(app_storage["autoCheckForUpdates"], "false")
        self.assertEqual(app_storage["runInBackground"], "false")

        self.assertTrue((pdir / "home" / ".local" / "bin").exists())
        self.assertTrue((pdir / "home" / ".cargo" / "bin").exists())
        self.assertFalse((pdir / "home" / ".ssh").exists())
        self.assertFalse((pdir / "home" / ".npmrc").exists())

        audit = audit_profile_isolation(pdir, manifest)
        self.assertTrue(audit["zshenv_home_locked"])
        self.assertEqual(audit["forbidden_symlinks_present"], [])

    def test_forbidden_symlinks_are_rejected_and_removed(self) -> None:
        for forbidden in [".gemini", ".gemini/antigravity", ".gemini/jetski-standalone-oauth-token"]:
            with self.assertRaises(ToolError):
                validate_link_relpath(forbidden)

        manifest = ProfileManifest(
            schema_version=1,
            name="safe",
            label="Safe",
            accent="#10B981",
            default_target="hub",
            link_policy="none",
            auth_mode="isolated-file",
        )
        provision_profile_dirs(self.root, manifest, real_home=self.fake_home)
        pdir = self.root / "safe"
        bad_gemini = pdir / "home" / ".gemini"
        # Replace .gemini dir with a symlink into fake_home and verify re-provision strips it.
        for child in list(bad_gemini.rglob("*"))[::-1]:
            if child.is_dir() and not child.is_symlink():
                child.rmdir()
            else:
                child.unlink()
        bad_gemini.rmdir()
        try:
            bad_gemini.symlink_to(self.fake_home)
        except OSError as exc:
            if sys.platform == "win32" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink privilege (Developer Mode) required for symlink test")
            raise
        self.assertTrue(bad_gemini.is_symlink())

        provision_profile_dirs(self.root, manifest, real_home=self.fake_home)
        self.assertFalse(bad_gemini.is_symlink())
        self.assertTrue(bad_gemini.is_dir())

    def test_secret_scrubber_and_fail_closed_malformed_mcp(self) -> None:
        raw = json.dumps(
            {
                "mcpServers": {
                    "linear": {
                        "command": "npx",
                        "args": ["-y", "mcp-remote", "--token=secret123", "PORT=3000"],
                        "env": {
                            "LINEAR_API_KEY": "lin_api_abc123",
                            "NODE_ENV": "production",
                        },
                        "headers": {
                            "Authorization": "Bearer topsecret",
                            "X-Custom-Safe": "keep-me",
                        },
                        "url": "https://user:pass@mcp.example.com/sse?api_key=xyz&mode=fast",
                    }
                }
            }
        )
        scrubbed, hits = sanitize_mcp_json_text(raw, "mcp_config.json")
        self.assertGreaterEqual(hits, 5)
        srv = scrubbed["mcpServers"]["linear"]
        self.assertEqual(srv["env"]["LINEAR_API_KEY"], REDACTED_MARKER)
        self.assertEqual(srv["env"]["NODE_ENV"], "production")
        self.assertEqual(srv["headers"]["Authorization"], REDACTED_MARKER)
        self.assertEqual(srv["headers"]["X-Custom-Safe"], "keep-me")
        self.assertIn(REDACTED_MARKER, srv["args"][2])
        self.assertEqual(srv["args"][3], "PORT=3000")
        self.assertIn("https://[REDACTED]@mcp.example.com/sse", srv["url"])
        self.assertIn("api_key=REDACTED", srv["url"])
        self.assertIn("mode=fast", srv["url"])

        with self.assertRaises(ToolError) as cm:
            sanitize_mcp_json_text("{malformed-json", "mcp_config.json")
        self.assertEqual(cm.exception.code, "mcp_config_malformed")

    def test_inherit_config_fails_closed_on_malformed_host_mcp(self) -> None:
        gemini_dir = self.fake_home / ".gemini" / "antigravity"
        gemini_dir.mkdir(parents=True)
        (gemini_dir / "mcp_config.json").write_text("{not-valid-json", encoding="utf-8")

        ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        with self.assertRaises(ToolError) as cm:
            call_tool("profile_create", {"name": "rollback-test", "inherit_config": True}, ctx)
        self.assertEqual(cm.exception.code, "mcp_config_malformed")
        # Rollback ensures partial profile directory is removed on fail-closed error.
        self.assertFalse((self.root / "rollback-test").exists())

    def test_inherit_config_copies_sanitized_files_as_0600(self) -> None:
        gemini_dir = self.fake_home / ".gemini" / "antigravity"
        gemini_dir.mkdir(parents=True)
        (self.fake_home / ".gemini" / "GEMINI.md").write_text("# Instructions\n", encoding="utf-8")
        (gemini_dir / "mcp_config.json").write_text(
            json.dumps({"mcpServers": {"github": {"env": {"GITHUB_TOKEN": "gh" + "p_" + "a" * 30}}}}),
            encoding="utf-8",
        )
        ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        res = call_tool("profile_create", {"name": "inherited", "inherit_config": True}, ctx)
        self.assertEqual(res["inherited"]["redacted_secrets"], 1)
        copied_mcp = self.root / "inherited" / "home" / ".gemini" / "antigravity" / "mcp_config.json"
        if sys.platform != "win32":
            self.assertEqual(copied_mcp.stat().st_mode & 0o777, 0o600)
        loaded = json.loads(copied_mcp.read_text(encoding="utf-8"))
        self.assertEqual(loaded["mcpServers"]["github"]["env"]["GITHUB_TOKEN"], REDACTED_MARKER)

    def test_upgrade_cache_purge(self) -> None:
        manifest = ProfileManifest(
            schema_version=1,
            name="upgrade",
            label="Upgrade",
            accent="#3B82F6",
            default_target="hub",
            link_policy="none",
            auth_mode="isolated-file",
            last_host_versions={"hub": "2.31.0"},
        )
        provision_profile_dirs(self.root, manifest, real_home=self.fake_home)
        pdir = self.root / "upgrade"
        stale_cache = pdir / "data" / "GPUCache"
        stale_cache.mkdir()
        (stale_cache / "blob").write_text("stale", encoding="utf-8")
        targets = {
            "hub": TargetInfo(
                kind="hub",
                display_name="Antigravity Hub",
                app_path="/Applications/Antigravity.app",
                binary_path="/bin/true",
                bundle_id="com.google.antigravity",
                version="2.32.1",
                installed=True,
            ),
            "ide": TargetInfo(
                kind="ide",
                display_name="Antigravity IDE",
                app_path="/Applications/Antigravity IDE.app",
                binary_path=None,
                bundle_id="com.google.antigravity-ide",
                version="",
                installed=False,
            ),
        }
        purged = purge_stale_caches_if_upgraded(pdir, manifest, targets)
        self.assertIn("data/GPUCache", purged)
        self.assertFalse(stale_cache.exists())
        self.assertEqual(manifest.last_host_versions["hub"], "2.32.1")

    def test_resolve_profiles_root_env_override(self) -> None:
        old = os.environ.get("AGY_PROFILES_DIR")
        try:
            os.environ["AGY_PROFILES_DIR"] = str(self.root)
            self.assertEqual(resolve_profiles_root(), self.root)
        finally:
            if old is None:
                os.environ.pop("AGY_PROFILES_DIR", None)
            else:
                os.environ["AGY_PROFILES_DIR"] = old

    def test_load_missing_manifest_raises(self) -> None:
        with self.assertRaises(ToolError) as cm:
            load_manifest(self.root, "nonexistent")
        self.assertEqual(cm.exception.code, "profile_not_found")

    def test_detect_profile_and_host_account_without_token_leak(self) -> None:
        ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        call_tool("profile_create", {"name": "acct-check", "label": "Acct Check"}, ctx)
        profile_dir, _ = load_manifest(self.root, "acct-check")
        secret_tok = "tok" + "_do_not_expose_12345"
        token_path = profile_dir / "home" / ".gemini" / "jetski-standalone-oauth-token"
        token_path.write_text(
            json.dumps(
                {
                    "token": secret_tok,
                    "id_token_email": "alice@example.com",
                    "auth_method": "consumer",
                }
            ),
            encoding="utf-8",
        )
        os.chmod(str(token_path), 0o600)

        acct = detect_profile_account(profile_dir)
        self.assertEqual(acct["email"], "alice@example.com")
        self.assertEqual(acct["source"], "oauth_token")
        self.assertEqual(acct["auth_method"], "consumer")
        self.assertTrue(acct["oauth_present"])
        self.assertNotIn(secret_tok, json.dumps(acct))
        self.assertNotIn("token", acct)

        jwt_payload = base64.urlsafe_b64encode(b'{"email":"jwt-user@example.com"}').decode("ascii").rstrip("=")
        token_path.write_text(
            json.dumps({"token": secret_tok, "id_token": "hdr.{}.sig".format(jwt_payload)}),
            encoding="utf-8",
        )
        jwt_acct = detect_profile_account(profile_dir)
        self.assertEqual(jwt_acct["email"], "jwt-user@example.com")

        app_dir = self.fake_home / "Library" / "Application Support" / "Antigravity"
        app_dir.mkdir(parents=True)
        (app_dir / "app_storage.json").write_text(
            json.dumps({"agy.onboarding.lastLoginUsername": "bob@example.com"}),
            encoding="utf-8",
        )
        (self.fake_home / ".gemini" / "config" / "projects").mkdir(parents=True)
        (self.fake_home / ".gemini" / "config" / "projects" / "p1.json").write_text(
            json.dumps({"id": "p1", "name": "DemoProj"}),
            encoding="utf-8",
        )
        (self.fake_home / ".gemini" / "config" / "plugins" / "plug1").mkdir(parents=True)
        (self.fake_home / ".gemini" / "config" / "agents").mkdir(parents=True)
        (self.fake_home / ".gemini" / "config" / "agents" / "reviewer.md").write_text("# Reviewer\n", encoding="utf-8")

        host_acct = detect_host_account(real_home=self.fake_home)
        self.assertEqual(host_acct["email"], "bob@example.com")
        self.assertEqual(host_acct["projects_count"], 1)
        self.assertEqual(host_acct["plugins_count"], 1)
        self.assertEqual(host_acct["agents_count"], 1)

    def test_sync_host_customizations_strips_sidecars_dedupes_mcp_and_links_agents(self) -> None:
        (self.fake_home / ".agents" / "skills" / "demo").mkdir(parents=True)
        (self.fake_home / ".agents" / "skills" / "demo" / "SKILL.md").write_text("# Demo\n", encoding="utf-8")

        host_gemini = self.fake_home / ".gemini"
        (host_gemini / "config" / "projects").mkdir(parents=True)
        (host_gemini / "config" / "agents").mkdir(parents=True)
        (host_gemini / "config" / "plugins" / "plug-a").mkdir(parents=True)
        (host_gemini / "config" / "skills" / "skill-a").mkdir(parents=True)
        (host_gemini / "antigravity").mkdir(parents=True)

        fake_bearer = "Bearer " + "secretvalue123456789"
        cfg_mcp = host_gemini / "config" / "mcp_config.json"
        cfg_mcp.write_text(
            json.dumps({"mcpServers": {"s1": {"headers": {"Authorization": fake_bearer}}}}),
            encoding="utf-8",
        )
        try:
            os.symlink("../config/mcp_config.json", str(host_gemini / "antigravity" / "mcp_config.json"))
        except OSError as exc:
            if sys.platform == "win32" and getattr(exc, "winerror", None) == 1314:
                create_safe_link(cfg_mcp, host_gemini / "antigravity" / "mcp_config.json")
            else:
                raise

        (host_gemini / "config" / "config.json").write_text(
            json.dumps({"theme": "dark", "sidecars": {"daily-cron": {"schedule": "0 14 * * *"}}}),
            encoding="utf-8",
        )
        (host_gemini / "config" / "projects" / "p1.json").write_text(
            json.dumps({"id": "p1", "name": "DemoProj", "sidecar": {"cron": "*/5 * * * *"}}),
            encoding="utf-8",
        )
        (host_gemini / "config" / "agents" / "architect.md").write_text("# Architect\n", encoding="utf-8")
        (host_gemini / "config" / "plugins" / "plug-a" / "plugin.json").write_text('{"name":"plug-a"}\n', encoding="utf-8")
        (host_gemini / "config" / "skills" / "skill-a" / "SKILL.md").write_text("# Skill A\n", encoding="utf-8")

        ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        created = call_tool(
            "profile_create",
            {"name": "dev-sync", "label": "Dev Sync", "link_policy": "dev", "inherit_config": True},
            ctx,
        )
        profile_dir = Path(created["paths"]["profile_dir"])
        self.assertTrue((profile_dir / "home" / ".agents").exists())

        sync_res = sync_host_customizations(profile_dir, real_home=self.fake_home, include_sidecars=False)
        self.assertGreaterEqual(sync_res["redacted_secrets"], 1)
        self.assertEqual(sync_res["stripped_sidecars"], 2)
        self.assertEqual(sync_res["projects_synced"], 1)
        self.assertEqual(sync_res["plugins_synced"], 1)
        self.assertEqual(sync_res["agents_synced"], 1)
        self.assertEqual(sync_res["skills_synced"], 1)

        sandbox_cfg = json.loads((profile_dir / "home" / ".gemini" / "config" / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(sandbox_cfg["sidecars"], {})
        sandbox_proj = json.loads((profile_dir / "home" / ".gemini" / "config" / "projects" / "p1.json").read_text(encoding="utf-8"))
        self.assertNotIn("sidecar", sandbox_proj)

        _, manifest = load_manifest(self.root, "dev-sync")
        iso = audit_profile_isolation(profile_dir, manifest)
        if sys.platform != "win32":
            self.assertEqual(iso["permissions"]["mcp_config_file"], "0o600")
        self.assertEqual(iso["sync_state"]["projects_count"], 1)
        self.assertEqual(iso["sync_state"]["agents_count"], 1)

    def test_collect_host_handoff_and_idempotent_gemini_pointer(self) -> None:
        host_gemini = self.fake_home / ".gemini"
        (host_gemini / "config" / "projects").mkdir(parents=True)
        (host_gemini / "config" / "projects" / "p1.json").write_text(
            json.dumps({"id": "p1", "name": "WorkingDaily"}),
            encoding="utf-8",
        )
        (host_gemini / "GEMINI.md").write_text("# Base Rules\n", encoding="utf-8")

        agy_dir = host_gemini / "antigravity"
        (agy_dir / "annotations").mkdir(parents=True)
        brain_logs = agy_dir / "brain" / "conv-1" / ".system_generated" / "logs"
        brain_logs.mkdir(parents=True)

        db_path = agy_dir / "conversation_summaries.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """
            CREATE TABLE conversation_summaries (
                conversation_id TEXT PRIMARY KEY,
                title TEXT,
                preview TEXT,
                last_modified_time TEXT,
                workspace_uris TEXT,
                status TEXT,
                project_id TEXT,
                parent_conversation_id TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("conv-1", "", "fallback preview", "2026-11-15 10:00:00+00:00", '["file:///tmp/DemoRepo"]', "CASCADE_RUN_STATUS_IDLE", "p1", ""),
        )
        conn.execute(
            "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("conv-sub", "Subagent", "hidden", "2026-11-15 10:05:00+00:00", '[]', "CASCADE_RUN_STATUS_IDLE", "p1", "conv-1"),
        )
        conn.commit()
        conn.close()

        (agy_dir / "annotations" / "conv-1.pbtxt").write_text('title: "Ship profile handoff"\n', encoding="utf-8")
        leaked_ghp = "gh" + "p_1234567890abcdef"
        steps = [
            {"type": "USER_INPUT", "content": "<CONTEXT_SUMMARY>internal</CONTEXT_SUMMARY>Finish phase \u2014 two using " + leaked_ghp},
            {"type": "PLANNER_RESPONSE", "content": "Implemented backend validation cleanly."},
        ]
        brain_logs.joinpath("transcript.jsonl").write_text(
            "\n".join(json.dumps(s) for s in steps) + "\n",
            encoding="utf-8",
        )

        digest = collect_host_handoff(real_home=self.fake_home, limit=5)
        self.assertTrue(digest["available"])
        self.assertEqual(digest["count"], 1)
        conv = digest["conversations"][0]
        self.assertEqual(conv["title"], "Ship profile handoff")
        self.assertEqual(conv["project"], "WorkingDaily")
        self.assertNotIn("\u2014", conv["last_user_request"])
        self.assertNotIn(leaked_ghp, conv["last_user_request"])
        self.assertIn(REDACTED_MARKER, conv["last_user_request"])

        ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        call_tool("profile_create", {"name": "handoff-box", "label": "Handoff Box"}, ctx)
        profile_dir, _ = load_manifest(self.root, "handoff-box")
        sync_host_customizations(profile_dir, real_home=self.fake_home, include_handoff=True)
        sync_host_customizations(profile_dir, real_home=self.fake_home, include_handoff=True)

        handoff_md = profile_dir / "home" / ".gemini" / "HANDOFF_CONTEXT.md"
        self.assertTrue(handoff_md.is_file())
        if sys.platform != "win32":
            self.assertEqual(oct(handoff_md.stat().st_mode & 0o777), "0o600")
        self.assertNotIn("\u2014", handoff_md.read_text(encoding="utf-8"))

        gemini_text = (profile_dir / "home" / ".gemini" / "GEMINI.md").read_text(encoding="utf-8")
        self.assertEqual(gemini_text.count(HANDOFF_START_MARKER), 1)
        _ = write_handoff_context

    def test_automations_migration_paused_active_strip_and_prune(self) -> None:
        host_gemini = self.fake_home / ".gemini"
        (host_gemini / "config" / "sidecars" / "auto-one").mkdir(parents=True)
        (host_gemini / "config" / "projects").mkdir(parents=True)
        (host_gemini / "config" / "skills" / "skill-live").mkdir(parents=True)
        (host_gemini / "config" / "skills" / "skill-live" / "SKILL.md").write_text("# Live\n", encoding="utf-8")
        (host_gemini / "config" / "hooks.json").write_text('{"PreInvocation": []}\n', encoding="utf-8")

        fake_tok = "sk-proj-" + "secret1234567890"
        host_sidecar_payload = {
            "builtin": "schedule",
            "display_name": "Auto One",
            "args": [
                "CRON_TZ=UTC 0 9 * * *",
                "agentapi",
                "new-conversation",
                "--",
                "Write report to {}/antigravity/sidecar_data/auto-one/out.json using {}".format(
                    host_gemini, fake_tok
                ),
            ],
            "agent_permissions": {
                "access_grants": [
                    "write_file({}/antigravity/sidecar_data/auto-one/out.json)".format(host_gemini),
                ],
                "workspace_uris": ["file:///Volumes/Dev/sample-repo"],
            },
        }
        (host_gemini / "config" / "sidecars" / "auto-one" / "sidecar.json").write_text(
            json.dumps(host_sidecar_payload),
            encoding="utf-8",
        )
        (host_gemini / "config" / "config.json").write_text(
            json.dumps(
                {
                    "sidecars": {
                        "auto-one": {
                            "enabled": True,
                            "projectId": "p1",
                            "resolvedPermissions": {
                                "accessGrants": [
                                    "read_file({}/config/skills/skill-live/SKILL.md)".format(host_gemini)
                                ],
                                "workspaceUris": ["file:///Volumes/Dev/sample-repo"],
                            },
                            "schemaVersion": 1,
                        },
                        "stale-deleted-cron": {"enabled": True, "schemaVersion": 1},
                        "swarm/swarm_board": None,
                    }
                }
            ),
            encoding="utf-8",
        )
        (host_gemini / "config" / "projects" / "p1.json").write_text(
            json.dumps({"id": "p1", "name": "LiveProj", "sidecar": {"sidecarId": "auto-one"}}),
            encoding="utf-8",
        )
        deleted_proj = host_gemini / "config" / "projects" / "p_stale.json"
        deleted_proj.write_text(json.dumps({"id": "p_stale", "name": "StaleProj"}), encoding="utf-8")
        stale_skill = host_gemini / "config" / "skills" / "skill-stale"
        stale_skill.mkdir(parents=True)
        (stale_skill / "SKILL.md").write_text("# Stale\n", encoding="utf-8")

        ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        created = call_tool("profile_create", {"name": "auto-box", "label": "Auto Box"}, ctx)
        profile_dir = Path(created["paths"]["profile_dir"])
        sandbox_gemini = profile_dir / "home" / ".gemini"

        # 1. Default paused standby: migrates sidecars, rewrites .gemini paths, disables enabled, strips orphans.
        res_paused = sync_host_customizations(profile_dir, real_home=self.fake_home, automations_mode="paused")
        self.assertEqual(res_paused["automations_mode"], "paused")
        self.assertEqual(res_paused["automations_synced"], 1)
        self.assertEqual(res_paused["automations_enabled"], 0)
        self.assertEqual(res_paused["projects_synced"], 2)
        self.assertEqual(res_paused["stripped_sidecars"], 1)
        self.assertGreaterEqual(res_paused["redacted_secrets"], 1)

        sandbox_sc_file = sandbox_gemini / "config" / "sidecars" / "auto-one" / "sidecar.json"
        self.assertTrue(sandbox_sc_file.is_file())
        sc_text = sandbox_sc_file.read_text(encoding="utf-8")
        sc_data = json.loads(sc_text)
        self.assertIn(str(sandbox_gemini), sc_data["args"][-1])
        self.assertNotIn(str(host_gemini), sc_text)
        self.assertNotIn(fake_tok, sc_text)
        self.assertTrue((sandbox_gemini / "antigravity" / "sidecar_data" / "auto-one").is_dir())
        self.assertTrue((sandbox_gemini / "config" / "hooks.json").is_file())

        sandbox_cfg = json.loads((sandbox_gemini / "config" / "config.json").read_text(encoding="utf-8"))
        self.assertFalse(sandbox_cfg["sidecars"]["auto-one"]["enabled"])
        self.assertNotIn("stale-deleted-cron", sandbox_cfg["sidecars"])
        self.assertIn("swarm/swarm_board", sandbox_cfg["sidecars"])

        # 2. Delete a Host project and skill, then sync in active mode -> stale entries pruned, automation enabled.
        deleted_proj.unlink()
        (stale_skill / "SKILL.md").unlink()
        stale_skill.rmdir()
        res_active = sync_host_customizations(profile_dir, real_home=self.fake_home, automations_mode="active")
        self.assertEqual(res_active["automations_enabled"], 1)
        self.assertEqual(res_active["projects_synced"], 1)
        self.assertGreaterEqual(res_active["pruned_entries"], 2)
        self.assertFalse((sandbox_gemini / "config" / "projects" / "p_stale.json").exists())
        self.assertFalse((sandbox_gemini / "config" / "skills" / "skill-stale").exists())
        sandbox_cfg_active = json.loads((sandbox_gemini / "config" / "config.json").read_text(encoding="utf-8"))
        self.assertTrue(sandbox_cfg_active["sidecars"]["auto-one"]["enabled"])
        sandbox_p1 = json.loads((sandbox_gemini / "config" / "projects" / "p1.json").read_text(encoding="utf-8"))
        self.assertEqual(sandbox_p1["sidecar"]["sidecarId"], "auto-one")

        # 3. Strip mode removes scheduled sidecar definitions and project sidecar links.
        res_strip = sync_host_customizations(profile_dir, real_home=self.fake_home, automations_mode="strip")
        self.assertEqual(res_strip["automations_synced"], 0)
        self.assertEqual(res_strip["automations_enabled"], 0)
        self.assertFalse((sandbox_gemini / "config" / "sidecars" / "auto-one").exists())
        sandbox_p1_stripped = json.loads((sandbox_gemini / "config" / "projects" / "p1.json").read_text(encoding="utf-8"))
        self.assertNotIn("sidecar", sandbox_p1_stripped)

    def test_bidirectional_handoff_from_profile(self) -> None:
        ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        call_tool("profile_create", {"name": "backup-box", "label": "backup@example.com"}, ctx)
        profile_dir, _ = load_manifest(self.root, "backup-box")
        sandbox_gemini = profile_dir / "home" / ".gemini"
        (sandbox_gemini / "antigravity").mkdir(parents=True, exist_ok=True)
        (sandbox_gemini / "jetski-standalone-oauth-token").write_text(
            json.dumps({"id_token_email": "backup@example.com"}),
            encoding="utf-8",
        )
        db_path = sandbox_gemini / "antigravity" / "conversation_summaries.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """
            CREATE TABLE conversation_summaries (
                conversation_id TEXT PRIMARY KEY,
                title TEXT,
                preview TEXT,
                last_modified_time TEXT,
                workspace_uris TEXT,
                status TEXT,
                project_id TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO conversation_summaries VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("conv-b1", "Fix backup sync", "Verified backup PR", "2026-11-16 09:00:00+00:00", '["file:///tmp/DemoRepo"]', "CASCADE_RUN_STATUS_IDLE", "p1"),
        )
        conn.commit()
        conn.close()

        digest = call_tool("host_handoff", {"source": "backup-box", "limit": 5}, ctx)
        self.assertTrue(digest["available"])
        self.assertEqual(digest["source"], "backup-box")
        self.assertEqual(digest["source_account"], "backup@example.com")
        self.assertEqual(digest["count"], 1)
        self.assertIn("backup-box (backup@example.com)", digest["resume_prompt"])

    def test_obligations_doc_matches_live_obligation_ids(self) -> None:
        ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        report = call_tool("obligations_verify", {}, ctx)
        obl_doc = (Path(__file__).resolve().parents[1] / "docs" / "OBLIGATIONS.md").read_text(encoding="utf-8")
        for item in report["items"]:
            self.assertIn(item["obligation_id"], obl_doc)

    def test_token_prefix_scrubber_preserves_desk_production_hostname_while_redacting_real_sk_tokens(self) -> None:
        from agy_profiles.isolation import TOKEN_PREFIX_RE

        url_grant = "read_url(gambler-day-desk-production.up.railway.app)"
        self.assertIsNone(TOKEN_PREFIX_RE.search(url_grant))
        fake_key = "Bearer " + "sk-" + "live1234567890abcdef"
        self.assertIsNotNone(TOKEN_PREFIX_RE.search(fake_key))


if __name__ == "__main__":
    unittest.main()
