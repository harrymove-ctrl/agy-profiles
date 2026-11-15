"""Hardened loopback-only HTTP server with Host, Cookie, CSRF, and Origin guards."""

from __future__ import annotations

import hashlib
import hmac
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import threading
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from agy_profiles import __version__
from agy_profiles.errors import ToolError
from agy_profiles.tools import RuntimeContext, call_tool

ALLOWED_BIND_HOSTS = ("127.0.0.1", "::1")
MAX_BODY_BYTES = 256 * 1024
SESSION_COOKIE_NAME = "__agy_session"
STATIC_DIR = Path(__file__).resolve().parent / "web_static"

CSP_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)


def validate_bind_host(host: str) -> str:
    """Restrict HTTP bind addresses strictly to IPv4 or IPv6 loopback."""
    clean = (host or "").strip()
    if clean not in ALLOWED_BIND_HOSTS:
        raise ToolError(
            "invalid_host_bind",
            "Refusing to bind local console to non-loopback address {!r}.".format(host),
            "Bind strictly to '127.0.0.1' or '::1'.",
            {"host": host},
            http_status=400,
        )
    return clean


def format_host_header(host: str, port: int) -> str:
    """Format canonical HTTP Host authority for IPv4 or IPv6 loopback."""
    if ":" in host and not host.startswith("["):
        return "[{}]:{}".format(host, port)
    return "{}:{}".format(host, port)


def constant_time_equal(left: str, right: str) -> bool:
    """Compare two secrets in constant time."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def validate_host_header(host_header: Optional[str], expected_host: str) -> bool:
    """Defend against DNS rebinding by requiring exact Host:Port match."""
    if not host_header:
        return False
    return constant_time_equal(host_header.strip(), expected_host)


def validate_mutation_origin(origin_header: Optional[str], expected_origin: str) -> bool:
    """Reject missing Origin, Origin: null, and any cross-origin mutating requests."""
    if not origin_header:
        return False
    stripped = origin_header.strip()
    if not stripped or stripped.lower() == "null":
        return False
    return constant_time_equal(stripped, expected_origin)


class ServerSecurityState:
    """Per-run cryptographic tokens and request verification helpers."""

    def __init__(self, ctx: RuntimeContext, host: str, port: int) -> None:
        self.ctx = ctx
        self.host = validate_bind_host(host)
        self.port = port
        self.bootstrap_token = secrets.token_urlsafe(32)
        self.session_secret = secrets.token_bytes(32)
        self.csrf_token = secrets.token_urlsafe(32)
        self.expected_host = format_host_header(self.host, self.port)
        self.expected_origin = "http://{}".format(self.expected_host)

    def update_port(self, actual_port: int) -> None:
        """Bind actual OS-assigned port after socket creation."""
        self.port = int(actual_port)
        self.expected_host = format_host_header(self.host, self.port)
        self.expected_origin = "http://{}".format(self.expected_host)

    def create_session_cookie_value(self) -> str:
        """Create HMAC-SHA256 authenticated session cookie value."""
        nonce = secrets.token_urlsafe(24)
        sig = hmac.new(self.session_secret, nonce.encode("utf-8"), hashlib.sha256).hexdigest()
        return "{}.{}".format(nonce, sig)

    def verify_session_cookie_header(self, cookie_header: Optional[str]) -> bool:
        """Verify __agy_session cookie signature in constant time."""
        if not cookie_header:
            return False
        jar = cookies.SimpleCookie()
        try:
            jar.load(cookie_header)
        except cookies.CookieError:
            return False
        morsel = jar.get(SESSION_COOKIE_NAME)
        if morsel is None or "." not in morsel.value:
            return False
        nonce, provided_sig = morsel.value.split(".", 1)
        if not nonce or not provided_sig:
            return False
        expected_sig = hmac.new(
            self.session_secret,
            nonce.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(provided_sig, expected_sig)

    @property
    def tokenized_url(self) -> str:
        """Return initial authenticated browser URL carrying one-time query bootstrap token."""
        return "{}/?token={}".format(self.expected_origin, self.bootstrap_token)


class DualStackLoopbackHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server supporting strict IPv4 or IPv6 loopback binds."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        request_handler_class: Any,
        security_state: ServerSecurityState,
    ) -> None:
        if ":" in server_address[0]:
            self.address_family = socket.AF_INET6
        self.security_state = security_state
        super().__init__(server_address, request_handler_class)
        self.security_state.update_port(self.server_address[1])


def _render_index_html(csrf_token: str) -> bytes:
    html_text = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    rendered = html_text.replace("__AGY_CSRF_TOKEN__", csrf_token)
    return rendered.encode("utf-8")


def _unauthorized_html() -> bytes:
    body = (
        "<!doctype html>"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>AGY Profiles Authentication Required</title>"
        "<style>"
        "body{margin:0;background:#0b0e13;color:#e8eef5;font:14px/1.6 system-ui,-apple-system,sans-serif;display:grid;place-items:center;min-height:100vh}"
        ".card{max-width:460px;background:#11161e;border:1px solid #222b38;border-radius:10px;padding:24px}"
        "h1{margin:0 0 8px;font-size:16px}p{margin:0;color:#94a3b8}"
        "</style></head><body><div class=\"card\">"
        "<h1>Session Token Required</h1>"
        "<p>Open the tokenized URL printed in your terminal running <code>agy-profiles web</code> to start a local console session.</p>"
        "</div></body></html>"
    )
    return body.encode("utf-8")


class HardenedWebHandler(BaseHTTPRequestHandler):
    """HTTP handler enforcing Host, Session Cookie, CSRF Header, Origin, and CSP."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr request dumps to avoid polluting stdio callers.
        return

    @property
    def state(self) -> ServerSecurityState:
        return self.server.security_state  # type: ignore[attr-defined]

    def _send_security_headers(self, content_type: str, content_length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Content-Security-Policy", CSP_POLICY)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _send_bytes(
        self,
        status: int,
        content_type: str,
        payload: bytes,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.send_response(status)
        self._send_security_headers(content_type, len(payload))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(data).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", payload)

    def _send_tool_error(self, exc: ToolError, status_override: Optional[int] = None) -> None:
        self._send_json(status_override or exc.http_status, exc.to_dict())

    def _check_host_or_reject(self) -> bool:
        if not validate_host_header(self.headers.get("Host"), self.state.expected_host):
            self._send_tool_error(
                ToolError(
                    "invalid_host",
                    "Rejected request with disallowed Host header.",
                    "Access the console strictly via {}.".format(self.state.expected_origin),
                    http_status=403,
                )
            )
            return False
        return True

    def _authenticate_api_request(self, require_origin: bool) -> bool:
        if not self.state.verify_session_cookie_header(self.headers.get("Cookie")):
            self._send_tool_error(
                ToolError(
                    "unauthorized",
                    "Missing or invalid local session cookie.",
                    "Open the authenticated URL printed by 'agy-profiles web'.",
                    http_status=401,
                )
            )
            return False

        provided_csrf = self.headers.get("X-AGY-CSRF", "")
        if not constant_time_equal(provided_csrf, self.state.csrf_token):
            self._send_tool_error(
                ToolError(
                    "csrf_rejected",
                    "Missing or invalid X-AGY-CSRF token.",
                    "Reload the console from the authenticated session URL.",
                    http_status=403,
                )
            )
            return False

        if require_origin:
            if not validate_mutation_origin(self.headers.get("Origin"), self.state.expected_origin):
                self._send_tool_error(
                    ToolError(
                        "csrf_rejected",
                        "Rejected mutating request with missing, null, or mismatched Origin.",
                        "Mutate profiles only from {}.".format(self.state.expected_origin),
                        http_status=403,
                    )
                )
                return False
        return True

    def _read_json_body(self) -> Optional[Dict[str, Any]]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None or raw_len.strip() == "":
            return {}
        try:
            length = int(raw_len.strip())
        except ValueError:
            self._send_tool_error(
                ToolError("invalid_argument", "Invalid Content-Length header.", http_status=400)
            )
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_tool_error(
                ToolError(
                    "invalid_argument",
                    "Request payload exceeds maximum 256 KiB limit.",
                    http_status=413,
                )
            )
            return None
        if length == 0:
            return {}
        raw_bytes = self.rfile.read(length)
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_tool_error(
                ToolError("invalid_argument", "Malformed JSON request body.", http_status=400)
            )
            return None
        if not isinstance(parsed, dict):
            self._send_tool_error(
                ToolError("invalid_argument", "JSON request body must be an object.", http_status=400)
            )
            return None
        return parsed

    def _serve_static_asset(self, filename: str, content_type: str) -> None:
        asset_path = STATIC_DIR / filename
        if not asset_path.is_file():
            self._send_json(404, ToolError("not_found", "Static asset not found.", http_status=404).to_dict())
            return
        self._send_bytes(200, content_type, asset_path.read_bytes())

    def do_GET(self) -> None:
        if not self._check_host_or_reject():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            qs = parse_qs(parsed.query)
            token_vals = qs.get("token", [])
            if token_vals and constant_time_equal(token_vals[0], self.state.bootstrap_token):
                cookie_val = self.state.create_session_cookie_value()
                cookie_hdr = "{}={}; HttpOnly; SameSite=Strict; Path=/".format(
                    SESSION_COOKIE_NAME, cookie_val
                )
                self._send_bytes(
                    200,
                    "text/html; charset=utf-8",
                    _render_index_html(self.state.csrf_token),
                    extra_headers={"Set-Cookie": cookie_hdr},
                )
                return
            if self.state.verify_session_cookie_header(self.headers.get("Cookie")):
                self._send_bytes(
                    200,
                    "text/html; charset=utf-8",
                    _render_index_html(self.state.csrf_token),
                )
                return
            self._send_bytes(401, "text/html; charset=utf-8", _unauthorized_html())
            return

        if path == "/styles.css":
            self._serve_static_asset("styles.css", "text/css; charset=utf-8")
            return
        if path == "/app.js":
            self._serve_static_asset("app.js", "application/javascript; charset=utf-8")
            return
        if path == "/mark.svg":
            self._serve_static_asset("mark.svg", "image/svg+xml")
            return

        if not path.startswith("/api/"):
            self._send_json(404, ToolError("not_found", "Route not found.", http_status=404).to_dict())
            return

        if not self._authenticate_api_request(require_origin=False):
            return

        try:
            if path == "/api/state":
                res = call_tool("profile_list", {}, self.state.ctx)
                res["server"] = {"version": __version__, "origin": self.state.expected_origin}
                self._send_json(200, res)
                return
            if path == "/api/doctor":
                self._send_json(200, call_tool("system_doctor", {}, self.state.ctx))
                return
            if path == "/api/obligations":
                self._send_json(200, call_tool("obligations_verify", {}, self.state.ctx))
                return
            parts = [unquote(seg) for seg in path.split("/") if seg]
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "profiles":
                self._send_json(200, call_tool("profile_inspect", {"name": parts[2]}, self.state.ctx))
                return
            self._send_json(404, ToolError("not_found", "API route not found.", http_status=404).to_dict())
        except ToolError as exc:
            self._send_tool_error(exc)

    def do_POST(self) -> None:
        if not self._check_host_or_reject():
            return
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self._send_json(404, ToolError("not_found", "Route not found.", http_status=404).to_dict())
            return
        if not self._authenticate_api_request(require_origin=True):
            return
        body = self._read_json_body()
        if body is None:
            return

        parts = [unquote(seg) for seg in parsed.path.split("/") if seg]
        try:
            if parts == ["api", "profiles"]:
                created = call_tool("profile_create", body, self.state.ctx)
                self._send_json(201, created)
                return
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "profiles":
                name, action = parts[2], parts[3]
                if action == "launch":
                    payload = dict(body)
                    payload["name"] = name
                    self._send_json(200, call_tool("profile_launch", payload, self.state.ctx))
                    return
                if action == "stop":
                    payload = dict(body)
                    payload["name"] = name
                    self._send_json(200, call_tool("profile_stop", payload, self.state.ctx))
                    return
                if action == "repair":
                    payload = dict(body)
                    payload["name"] = name
                    self._send_json(200, call_tool("profile_repair", payload, self.state.ctx))
                    return
                if action == "clone":
                    payload = dict(body)
                    payload["source"] = name
                    self._send_json(201, call_tool("profile_clone", payload, self.state.ctx))
                    return
                if action == "launcher":
                    payload = dict(body)
                    op = payload.pop("action", "build")
                    payload["name"] = name
                    tool_name = "launcher_remove" if op == "remove" else "launcher_build"
                    self._send_json(200, call_tool(tool_name, payload, self.state.ctx))
                    return
            self._send_json(404, ToolError("not_found", "API route not found.", http_status=404).to_dict())
        except ToolError as exc:
            self._send_tool_error(exc)

    def do_PATCH(self) -> None:
        if not self._check_host_or_reject():
            return
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self._send_json(404, ToolError("not_found", "Route not found.", http_status=404).to_dict())
            return
        if not self._authenticate_api_request(require_origin=True):
            return
        body = self._read_json_body()
        if body is None:
            return
        parts = [unquote(seg) for seg in parsed.path.split("/") if seg]
        try:
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "profiles":
                payload = dict(body)
                payload["name"] = parts[2]
                self._send_json(200, call_tool("profile_update", payload, self.state.ctx))
                return
            self._send_json(404, ToolError("not_found", "API route not found.", http_status=404).to_dict())
        except ToolError as exc:
            self._send_tool_error(exc)

    def do_DELETE(self) -> None:
        if not self._check_host_or_reject():
            return
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self._send_json(404, ToolError("not_found", "Route not found.", http_status=404).to_dict())
            return
        if not self._authenticate_api_request(require_origin=True):
            return
        body = self._read_json_body()
        if body is None:
            return
        parts = [unquote(seg) for seg in parsed.path.split("/") if seg]
        qs = parse_qs(parsed.query)
        try:
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "profiles":
                force_qs = qs.get("force_stop", ["false"])[0].lower() in ("1", "true", "yes")
                payload = {
                    "name": parts[2],
                    "confirm": True,
                    "force_stop": bool(body.get("force_stop", force_qs)),
                }
                self._send_json(200, call_tool("profile_delete", payload, self.state.ctx))
                return
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "profiles" and parts[3] == "launcher":
                payload = {"name": parts[2]}
                if "target" in body:
                    payload["target"] = body["target"]
                self._send_json(200, call_tool("launcher_remove", payload, self.state.ctx))
                return
            self._send_json(404, ToolError("not_found", "API route not found.", http_status=404).to_dict())
        except ToolError as exc:
            self._send_tool_error(exc)


def create_web_server(
    ctx: RuntimeContext,
    host: str = "127.0.0.1",
    port: int = 47920,
) -> DualStackLoopbackHTTPServer:
    """Create a hardened loopback HTTP server bound to host:port."""
    bind_host = validate_bind_host(host)
    sec_state = ServerSecurityState(ctx=ctx, host=bind_host, port=port)
    try:
        return DualStackLoopbackHTTPServer((bind_host, port), HardenedWebHandler, sec_state)
    except OSError:
        if port == 0:
            raise
        # Fall back cleanly to an ephemeral loopback port if default port is occupied.
        return DualStackLoopbackHTTPServer((bind_host, 0), HardenedWebHandler, sec_state)


def run_web_server_in_thread(
    ctx: RuntimeContext,
    host: str = "127.0.0.1",
    port: int = 0,
) -> Tuple[DualStackLoopbackHTTPServer, threading.Thread]:
    """Start loopback web server in a background daemon thread for tests or embedding."""
    httpd = create_web_server(ctx, host=host, port=port)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread
