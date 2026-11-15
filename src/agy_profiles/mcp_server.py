"""Line-delimited JSON-RPC 2.0 stdio MCP server exposing ToolSpec registry."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, IO, Optional

from agy_profiles import __version__
from agy_profiles.errors import ToolError
from agy_profiles.tools import RuntimeContext, call_tool, list_tools

PROTOCOL_VERSION = "2024-11-05"


def _jsonrpc_result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str, data: Optional[Any] = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def handle_mcp_request(raw_line: str, ctx: RuntimeContext) -> Optional[Dict[str, Any]]:
    """Process one JSON-RPC line and return response dict, or None for notifications."""
    stripped = raw_line.strip()
    if not stripped:
        return None
    try:
        msg = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return _jsonrpc_error(None, -32700, "Parse error: {}".format(exc.msg))

    if not isinstance(msg, dict):
        return _jsonrpc_error(None, -32600, "Invalid Request: expected JSON object.")

    req_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params")
    is_notification = "id" not in msg

    if not isinstance(method, str) or not method:
        if is_notification:
            return None
        return _jsonrpc_error(req_id, -32600, "Invalid Request: missing method string.")

    if method == "notifications/initialized" or method.startswith("notifications/"):
        return None

    if method == "initialize":
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "agy-profiles", "version": __version__},
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": list_tools()})

    if method == "tools/call":
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return _jsonrpc_error(req_id, -32602, "Invalid params: tools/call requires tool 'name'.")
        tool_name = params["name"]
        tool_args = params.get("arguments")
        if tool_args is not None and not isinstance(tool_args, dict):
            return _jsonrpc_error(req_id, -32602, "Invalid params: 'arguments' must be an object.")
        try:
            outcome = call_tool(tool_name, tool_args or {}, ctx)
            return _jsonrpc_result(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(outcome, indent=2),
                        }
                    ],
                    "isError": False,
                },
            )
        except ToolError as exc:
            return _jsonrpc_result(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(exc.to_dict(), indent=2),
                        }
                    ],
                    "isError": True,
                },
            )
        except Exception as exc:
            err_payload = ToolError(
                "internal_error",
                "Unexpected error executing {}: {}".format(tool_name, exc),
                "Inspect profile state with system_doctor.",
            ).to_dict()
            return _jsonrpc_result(
                req_id,
                {
                    "content": [{"type": "text", "text": json.dumps(err_payload, indent=2)}],
                    "isError": True,
                },
            )

    if is_notification:
        return None
    return _jsonrpc_error(req_id, -32601, "Method not found: {}".format(method))


def serve_mcp_stdio(
    ctx: RuntimeContext,
    stdin: Optional[IO[str]] = None,
    stdout: Optional[IO[str]] = None,
) -> int:
    """Serve line-delimited JSON-RPC 2.0 MCP requests over stdio until EOF."""
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout

    for line in in_stream:
        response = handle_mcp_request(line, ctx)
        if response is not None:
            out_stream.write(json.dumps(response, ensure_ascii=True) + "\n")
            out_stream.flush()
    return 0
