"""Tests for exact process-group matching, stale lock repair, launch isolation, and stop escalation."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agy_profiles.config import ProfileManifest, TargetInfo, save_manifest
from agy_profiles.errors import ToolError
from agy_profiles.isolation import provision_profile_dirs
from agy_profiles.process_guard import (
    command_matches_host_target,
    command_matches_user_data_dir,
    heal_electron_compositor,
    inspect_host_runtime,
    inspect_locks,
    launch_profile,
    list_profile_processes,
    repair_locks,
    stop_profile,
)


class ProcessGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "profiles"
        self.root.mkdir(mode=0o700)
        self.manifest = ProfileManifest(
            schema_version=1,
            name="work",
            label="Work",
            accent="#3B82F6",
            default_target="hub",
            link_policy="none",
            auth_mode="isolated-file",
        )
        provision_profile_dirs(self.root, self.manifest, real_home=self.base / "empty-home")
        self.profile_dir = self.root / "work"
        save_manifest(self.root, self.profile_dir, self.manifest)
        self.data_dir = str((self.profile_dir / "data").resolve())

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_exact_user_data_dir_boundary_matching(self) -> None:
        self.assertTrue(
            command_matches_user_data_dir(
                "/Applications/Antigravity.app/Contents/MacOS/Antigravity --user-data-dir={}".format(self.data_dir),
                self.data_dir,
            )
        )
        self.assertTrue(
            command_matches_user_data_dir(
                "/Applications/Antigravity.app/Contents/MacOS/Antigravity --user-data-dir={} --foo".format(self.data_dir),
                self.data_dir,
            )
        )
        # Sibling profile prefix must never match.
        self.assertFalse(
            command_matches_user_data_dir(
                "/Applications/Antigravity.app/Contents/MacOS/Antigravity --user-data-dir={}-2".format(self.data_dir),
                self.data_dir,
            )
        )
        self.assertFalse(
            command_matches_user_data_dir(
                "/bin/cat --flag --user-data-dir={}/nested".format(self.data_dir),
                self.data_dir,
            )
        )

    def test_descendant_bfs_process_discovery(self) -> None:
        rows = [
            {"pid": 100, "ppid": 1, "command": "Antigravity --user-data-dir={}".format(self.data_dir)},
            {"pid": 101, "ppid": 100, "command": "language_server_macos_arm64 --port=9000"},
            {"pid": 102, "ppid": 101, "command": "node mcp-worker.js"},
            {"pid": 200, "ppid": 1, "command": "Antigravity --user-data-dir={}-other".format(self.data_dir)},
        ]
        matched = list_profile_processes(self.profile_dir, ps_rows=rows)
        self.assertEqual([r["pid"] for r in matched["hub"]], [100, 101, 102])

    def test_inspect_host_runtime_isolates_host_from_sandboxes_and_counts_crons(self) -> None:
        fake_home = self.base / "host-home"
        fake_home.mkdir(mode=0o700)
        default_hub_dir = fake_home / "Library" / "Application Support" / "Antigravity"
        hub_bin = "/Applications/Antigravity.app/Contents/MacOS/Antigravity"
        ide_bin = "/Applications/Antigravity IDE.app/Contents/MacOS/Electron"

        self.assertTrue(command_matches_host_target(hub_bin, hub_bin, default_hub_dir))
        self.assertFalse(
            command_matches_host_target(
                "{} --type=renderer".format(hub_bin),
                hub_bin,
                default_hub_dir,
            )
        )
        self.assertFalse(
            command_matches_host_target(
                "{} --user-data-dir={}".format(hub_bin, self.data_dir),
                hub_bin,
                default_hub_dir,
            )
        )

        fake_targets = {
            "hub": TargetInfo(
                kind="hub",
                display_name="Antigravity Hub",
                app_path="/Applications/Antigravity.app",
                binary_path=hub_bin,
                bundle_id="com.google.antigravity",
                version="2.32.1",
                installed=True,
            ),
            "ide": TargetInfo(
                kind="ide",
                display_name="Antigravity IDE",
                app_path="/Applications/Antigravity IDE.app",
                binary_path=ide_bin,
                bundle_id="com.google.antigravity-ide",
                version="2.7.0",
                installed=True,
            ),
        }
        rows = [
            {"pid": 500, "ppid": 1, "command": hub_bin},
            {"pid": 501, "ppid": 500, "command": "/Applications/Antigravity.app/Contents/Frameworks/Helper --type=gpu-process"},
            {"pid": 502, "ppid": 500, "command": "language_server --standalone"},
            {"pid": 503, "ppid": 502, "command": "language_server multicall schedule CRON_TZ=UTC 0 * * * * echo one"},
            {"pid": 504, "ppid": 502, "command": "language_server multicall schedule CRON_TZ=UTC 30 * * * * echo two"},
            {"pid": 900, "ppid": 1, "command": "{} --user-data-dir={}".format(hub_bin, self.data_dir)},
            {"pid": 901, "ppid": 900, "command": "language_server multicall schedule CRON_TZ=UTC 15 * * * * echo sandbox"},
        ]
        host_rt = inspect_host_runtime(
            real_home=fake_home,
            targets=fake_targets,
            ps_rows=rows,
            allow_default_no_flag=True,
        )
        self.assertEqual(host_rt["hub"]["state"], "running")
        self.assertEqual(host_rt["hub"]["root_pids"], [500])
        self.assertEqual(host_rt["hub"]["pids"], [500, 501, 502, 503, 504])
        self.assertEqual(host_rt["hub"]["schedule_count"], 2)
        self.assertEqual(host_rt["ide"]["state"], "stopped")
        self.assertEqual(host_rt["ide"]["schedule_count"], 0)

        prof_rt = inspect_locks(self.profile_dir, "hub", ps_rows=rows)
        self.assertEqual(prof_rt["root_pids"], [900])
        self.assertEqual(prof_rt["schedule_count"], 1)

    def test_inspect_and_repair_stale_locks(self) -> None:
        lock_file = self.profile_dir / "data" / "SingletonLock"
        lock_file.write_text("999999", encoding="utf-8")

        state = inspect_locks(self.profile_dir, "hub", ps_rows=[])
        self.assertEqual(state["state"], "stale-lock")
        self.assertEqual(state["lock_files"], ["SingletonLock"])

        repaired = repair_locks(self.root, self.profile_dir, target="hub")
        self.assertIn("data/SingletonLock", repaired["removed"]["hub"])
        self.assertFalse(lock_file.exists())

    def test_repair_blocks_when_profile_running(self) -> None:
        rows = [{"pid": 555, "ppid": 1, "command": "Antigravity --user-data-dir={}".format(self.data_dir)}]
        with mock.patch("agy_profiles.process_guard.list_all_processes", return_value=rows):
            with self.assertRaises(ToolError) as cm:
                repair_locks(self.root, self.profile_dir, target="hub")
            self.assertEqual(cm.exception.code, "profile_running")

    def test_launch_profile_injects_sandbox_env_and_args(self) -> None:
        fake_targets = {
            "hub": TargetInfo(
                kind="hub",
                display_name="Antigravity Hub",
                app_path="/Applications/Antigravity.app",
                binary_path="/usr/bin/true",
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
        captured = {}

        class _FakeProc:
            pid = 4242

        def _fake_popen(argv, env=None, **_kwargs):
            captured["argv"] = argv
            captured["env"] = env
            return _FakeProc()

        with mock.patch("agy_profiles.process_guard.list_all_processes", return_value=[]), \
             mock.patch("agy_profiles.process_guard.detect_targets", return_value=fake_targets), \
             mock.patch("agy_profiles.process_guard.subprocess.Popen", side_effect=_fake_popen):
            res = launch_profile(self.root, self.profile_dir, self.manifest, target="hub")

        self.assertEqual(res["pid"], 4242)
        self.assertEqual(captured["argv"][0], "/usr/bin/true")
        self.assertIn("--user-data-dir={}".format(self.data_dir), captured["argv"])
        self.assertEqual(captured["env"]["HOME"], str((self.profile_dir / "home").resolve()))
        self.assertEqual(captured["env"]["ZDOTDIR"], str((self.profile_dir / "home").resolve()))
        self.assertEqual(captured["env"]["SSH_CONNECTION"], "local")

    def test_stop_profile_sigterm_and_sigkill_escalation(self) -> None:
        fake_proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import signal, sys, time; signal.signal(signal.SIGTERM, lambda *a: None); sys.stdout.write('READY\\n'); sys.stdout.flush(); time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            ready = fake_proc.stdout.readline().strip() if fake_proc.stdout else ""
            self.assertEqual(ready, "READY")

            def _dynamic_ps_rows():
                if fake_proc.poll() is None:
                    return [{"pid": fake_proc.pid, "ppid": 1, "command": "Antigravity --user-data-dir={}".format(self.data_dir)}]
                return []

            with mock.patch("agy_profiles.process_guard.list_all_processes", side_effect=_dynamic_ps_rows):
                result = stop_profile(self.root, self.profile_dir, target="hub", timeout_sec=0.25)
            self.assertIn(fake_proc.pid, result["signaled_pids"])
            if sys.platform != "win32":
                self.assertIn(fake_proc.pid, result["forced_pids"])
            fake_proc.wait(timeout=2)
        finally:
            if fake_proc.stdout:
                fake_proc.stdout.close()
            if fake_proc.poll() is None:
                fake_proc.kill()
                fake_proc.wait(timeout=2)

    def test_heal_electron_compositor_recycles_gpu_only_and_preserves_sessions(self) -> None:
        gpu_cache = Path(self.data_dir) / "GPUCache"
        gpu_cache.mkdir(parents=True, exist_ok=True)
        shader_blob = gpu_cache / "data_0"
        shader_blob.write_bytes(b"corrupted-metal-pipeline")

        fake_rows = [
            {
                "pid": 1001,
                "ppid": 1,
                "pgid": 1001,
                "command": "/Applications/Antigravity.app/Contents/MacOS/Antigravity --user-data-dir={}".format(self.data_dir),
            },
            {
                "pid": 1002,
                "ppid": 1001,
                "pgid": 1001,
                "command": "/Applications/Antigravity.app/Contents/Resources/bin/language_server --standalone",
            },
            {
                "pid": 1003,
                "ppid": 1001,
                "pgid": 1001,
                "command": "/Applications/Antigravity.app/Contents/Frameworks/Antigravity Helper.app/Contents/MacOS/Antigravity Helper --type=gpu-process --user-data-dir={}".format(self.data_dir),
            },
            {
                "pid": 1004,
                "ppid": 1001,
                "pgid": 1001,
                "command": "/Applications/Antigravity.app/Contents/Frameworks/Antigravity Helper (Renderer).app/Contents/MacOS/Antigravity Helper (Renderer) --type=renderer --user-data-dir={}".format(self.data_dir),
            },
        ]

        killed: list[tuple[int, int]] = []

        def _fake_kill(pid: int, sig: int) -> None:
            killed.append((pid, sig))

        with mock.patch("agy_profiles.process_guard.os.kill", side_effect=_fake_kill), \
             mock.patch("agy_profiles.process_guard.time.sleep"):
            res = heal_electron_compositor(
                scope="work",
                target="hub",
                deep=False,
                root=self.root,
                ps_rows=fake_rows,
            )

        self.assertEqual(res["recycled_gpu_pids"], [1003])
        self.assertEqual(res["recycled_renderer_pids"], [])
        self.assertEqual(res["preserved_root_pids"], [1001])
        self.assertFalse(shader_blob.exists())
        self.assertEqual([p for p, _ in killed], [1003])


if __name__ == "__main__":
    unittest.main()
