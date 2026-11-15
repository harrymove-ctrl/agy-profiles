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
from agy_profiles.mcp_server import handle_mcp_request, serve_mcp_stdio
from agy_profiles.tools import RuntimeContext


class McpAndCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "profiles"
        self.root.mkdir(mode=0o700)
        self.fake_home = Path(self.tmp.name).resolve() / "fake-home"
        self.fake_home.mkdir(mode=0o700)
        self.ctx = RuntimeContext(root=self.root, real_home=self.fake_home)

    def tearDown(self) -> None:
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
        self.assertIn("host_handoff", tool_names)
        self.assertGreaterEqual(len(tool_names), 15)

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
