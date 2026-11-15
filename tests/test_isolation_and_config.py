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
from agy_profiles.errors import ToolError
from agy_profiles.isolation import (
    REDACTED_MARKER,
    audit_profile_isolation,
    inherit_host_customizations,
    provision_profile_dirs,
    purge_stale_caches_if_upgraded,
    sanitize_mcp_json_text,
    validate_link_relpath,
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
        escape_link.symlink_to(outside)

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

        self.assertTrue((pdir / "home" / ".local" / "bin").is_symlink())
        self.assertTrue((pdir / "home" / ".cargo" / "bin").is_symlink())
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
        bad_gemini.symlink_to(self.fake_home)
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


if __name__ == "__main__":
    unittest.main()
