"""Hardened loopback-only HTTP server with Host, Cookie, CSRF, and Origin guards."""

from __future__ import annotations

import hashlib
import hmac
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import threading
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from agy_profiles import __version__
from agy_profiles.config import atomic_write_json
from agy_profiles.errors import ToolError
from agy_profiles.process_guard import heal_electron_compositor
from agy_profiles.tools import RuntimeContext, call_tool

ALLOWED_BIND_HOSTS = ("127.0.0.1", "::1")
MAX_BODY_BYTES = 256 * 1024
SESSION_COOKIE_NAME = "__agy_session"
SESSION_TTL_SECONDS = 365 * 86400
BOOTSTRAP_GRACE_SECONDS = 15.0
WEB_SECRETS_FILENAME = ".web-secrets.json"
STATIC_DIR = Path(__file__).resolve().parent / "web_static"

CSP_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

CSP_SIDECAR_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'self' https://127.0.0.1:* http://127.0.0.1:* https://localhost:* http://localhost:*; "
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


def load_or_create_web_secrets(root: Path) -> Tuple[bytes, str, str]:
    """Load or atomically initialize 0o600 persistent console secrets so daemon restarts never invalidate browser sessions."""
    secrets_path = root / WEB_SECRETS_FILENAME
    try:
        if secrets_path.is_file():
            raw = json.loads(secrets_path.read_text(encoding="utf-8"))
            sec_hex = str(raw.get("session_secret_hex") or "")
            csrf_tok = str(raw.get("csrf_token") or "")
            owner_tok = str(raw.get("owner_token") or "")
            if len(sec_hex) == 64 and len(csrf_tok) >= 32 and len(owner_tok) >= 32:
                return bytes.fromhex(sec_hex), csrf_tok, owner_tok
    except (OSError, ValueError, TypeError):
        pass

    session_secret = secrets.token_bytes(32)
    csrf_token = secrets.token_urlsafe(32)
    owner_token = secrets.token_urlsafe(32)
    try:
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(str(root), 0o700)
        atomic_write_json(
            secrets_path,
            {
                "session_secret_hex": session_secret.hex(),
                "csrf_token": csrf_token,
                "owner_token": owner_token,
            },
            mode=0o600,
        )
    except OSError:
        pass
    return session_secret, csrf_token, owner_token


class ServerSecurityState:
    """Per-run cryptographic tokens and request verification helpers."""

    def __init__(
        self,
        ctx: RuntimeContext,
        host: str,
        port: int,
        sidecar_mode: bool = False,
        sidecar_ui_token: str = "",
        preload_js_path: Optional[Path] = None,
    ) -> None:
        self.ctx = ctx
        self.host = validate_bind_host(host)
        self.port = port
        self.sidecar_mode = bool(sidecar_mode)
        self.sidecar_ui_token = sidecar_ui_token or ""
        self.preload_js_path = preload_js_path
        self.bootstrap_token = secrets.token_urlsafe(32)
        self._bootstrap_consumed_at: Optional[float] = None
        self._token_lock = threading.Lock()
        if self.sidecar_mode:
            self.session_secret = secrets.token_bytes(32)
            self.csrf_token = secrets.token_urlsafe(32)
            self.owner_token = ""
        else:
            self.session_secret, self.csrf_token, self.owner_token = load_or_create_web_secrets(ctx.root)
        self.expected_host = format_host_header(self.host, self.port)
        self.expected_origin = "http://{}".format(self.expected_host)

    def update_port(self, actual_port: int) -> None:
        """Bind actual OS-assigned port after socket creation."""
        self.port = int(actual_port)
        self.expected_host = format_host_header(self.host, self.port)
        self.expected_origin = "http://{}".format(self.expected_host)

    def verify_owner_token(self, candidate: str) -> bool:
        """Verify persistent local owner token stored in 0o600 .web-secrets.json."""
        if not candidate or not self.owner_token:
            return False
        return constant_time_equal(candidate, self.owner_token)

    def consume_bootstrap_token(self, candidate: str, now_mono: Optional[float] = None) -> bool:
        """Validate bootstrap query token once plus a short grace window for initial assets/reloads."""
        if not candidate or not constant_time_equal(candidate, self.bootstrap_token):
            return False
        ts = time.monotonic() if now_mono is None else float(now_mono)
        with self._token_lock:
            if self._bootstrap_consumed_at is None:
                self._bootstrap_consumed_at = ts
                return True
            return (ts - self._bootstrap_consumed_at) <= BOOTSTRAP_GRACE_SECONDS

    def create_session_cookie_value(self, now_epoch: Optional[int] = None) -> str:
        """Create timestamped HMAC-SHA256 authenticated session cookie value."""
        issued = int(time.time()) if now_epoch is None else int(now_epoch)
        nonce = secrets.token_urlsafe(24)
        payload = "{}.{}".format(issued, nonce)
        sig = hmac.new(self.session_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return "{}.{}".format(payload, sig)

    def verify_session_cookie_header(self, cookie_header: Optional[str], now_epoch: Optional[int] = None) -> bool:
        """Verify __agy_session cookie timestamp TTL and signature in constant time."""
        if not cookie_header:
            return False
        jar = cookies.SimpleCookie()
        try:
            jar.load(cookie_header)
        except cookies.CookieError:
            return False
        morsel = jar.get(SESSION_COOKIE_NAME)
        if morsel is None:
            return False
        parts = morsel.value.split(".")
        if len(parts) != 3:
            return False
        issued_str, nonce, provided_sig = parts
        if not issued_str or not nonce or not provided_sig:
            return False
        try:
            issued = int(issued_str)
        except ValueError:
            return False
        now = int(time.time()) if now_epoch is None else int(now_epoch)
        age = now - issued
        if age < -60 or age > SESSION_TTL_SECONDS:
            return False
        payload = "{}.{}".format(issued_str, nonce)
        expected_sig = hmac.new(
            self.session_secret,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(provided_sig, expected_sig)

    @property
    def tokenized_url(self) -> str:
        """Return initial authenticated browser URL carrying bootstrap token."""
        return "{}/?token={}".format(self.expected_origin, self.bootstrap_token)

    @property
    def owner_tokenized_url(self) -> str:
        """Return reusable local owner URL backed by 0o600 .web-secrets.json."""
        tok = self.owner_token or self.bootstrap_token
        return "{}/?token={}".format(self.expected_origin, tok)


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


def _render_index_html(csrf_token: str, sidecar_mode: bool = False) -> bytes:
    html_text = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    rendered = html_text.replace("__AGY_CSRF_TOKEN__", csrf_token)
    if sidecar_mode and "/preload.js" not in rendered:
        rendered = rendered.replace("</head>", '  <script src="/preload.js"></script>\n</head>', 1)
    return rendered.encode("utf-8")


def _unauthorized_html() -> bytes:
    body = (
        "<!doctype html>"
        "<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>AGY Profiles Authentication Required</title>"
        "<style>"
        "body{margin:0;background:#f7f5f0;color:#1c1917;font:14px/1.6 system-ui,-apple-system,sans-serif;display:grid;place-items:center;min-height:100vh}"
        ".card{max-width:460px;background:#ffffff;border:1px solid #e5e0d8;border-radius:12px;padding:28px;box-shadow:0 8px 24px rgba(28,25,23,0.06)}"
        "h1{margin:0 0 8px;font-size:18px;font-weight:600;color:#1c1917}p{margin:0;color:#57534e}"
        "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f1ede4;padding:2px 6px;border-radius:4px;color:#9a3412}"
        "</style></head><body><div class=\"card\">"
        "<h1>Session Token Required</h1>"
        "<p>Run <code>agyp daemon open</code> in your terminal once per browser to start a persistent 365 day local console session.</p>"
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
        self.send_header(
            "Content-Security-Policy",
            CSP_SIDECAR_POLICY if self.state.sidecar_mode else CSP_POLICY,
        )
        if not self.state.sidecar_mode:
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
        host_hdr = self.headers.get("Host")
        allowed = validate_host_header(host_hdr, self.state.expected_host)
        if not allowed and self.state.sidecar_mode:
            allowed = validate_host_header(host_hdr, "localhost:{}".format(self.state.port))
        if not allowed:
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

    def _check_mutation_origin(self) -> bool:
        origin_hdr = self.headers.get("Origin")
        if validate_mutation_origin(origin_hdr, self.state.expected_origin):
            return True
        if self.state.sidecar_mode and validate_mutation_origin(
            origin_hdr, "http://localhost:{}".format(self.state.port)
        ):
            return True
        self._send_tool_error(
            ToolError(
                "csrf_rejected",
                "Rejected mutating request with missing, null, or mismatched Origin.",
                "Mutate profiles only from {}.".format(self.state.expected_origin),
                http_status=403,
            )
        )
        return False

    def _has_valid_sidecar_token(self) -> bool:
        if not self.state.sidecar_mode or not self.state.sidecar_ui_token:
            return False
        provided = self.headers.get("X-Sidecar-Token", "")
        return bool(provided and constant_time_equal(provided, self.state.sidecar_ui_token))

    def _authenticate_api_request(self, require_origin: bool) -> bool:
        cookie_ok = self.state.verify_session_cookie_header(self.headers.get("Cookie"))
        if not cookie_ok and not self._has_valid_sidecar_token():
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
            if not self._check_mutation_origin():
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

    def _serve_font_asset(self, path: str) -> None:
        raw_rel = unquote(path[len("/fonts/"):])
        if (
            not raw_rel
            or "/" in raw_rel
            or "\\" in raw_rel
            or ".." in raw_rel
            or "\x00" in raw_rel
        ):
            self._send_json(404, ToolError("not_found", "Font asset not found.", http_status=404).to_dict())
            return
        if raw_rel.endswith(".woff2"):
            content_type = "font/woff2"
        elif raw_rel.endswith(".woff"):
            content_type = "font/woff"
        else:
            self._send_json(404, ToolError("not_found", "Font asset not found.", http_status=404).to_dict())
            return
        fonts_root = (STATIC_DIR / "fonts").resolve()
        candidate = (fonts_root / raw_rel).resolve()
        if candidate.parent != fonts_root or not candidate.is_file():
            self._send_json(404, ToolError("not_found", "Font asset not found.", http_status=404).to_dict())
            return
        self._send_bytes(
            200,
            content_type,
            candidate.read_bytes(),
            extra_headers={"Cache-Control": "public, max-age=31536000, immutable"},
        )

    def do_GET(self) -> None:
        if not self._check_host_or_reject():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            qs = parse_qs(parsed.query)
            token_vals = qs.get("token", [])
            has_valid_cookie = self.state.verify_session_cookie_header(self.headers.get("Cookie"))
            if self.state.sidecar_mode:
                if self.state.sidecar_ui_token:
                    token_ok = bool(token_vals and constant_time_equal(token_vals[0], self.state.sidecar_ui_token))
                    if not token_ok and not has_valid_cookie:
                        self._send_bytes(401, "text/html; charset=utf-8", _unauthorized_html())
                        return
                cookie_val = self.state.create_session_cookie_value()
                cookie_hdr = "{}={}; Max-Age={}; HttpOnly; SameSite=Lax; Path=/".format(
                    SESSION_COOKIE_NAME, cookie_val, SESSION_TTL_SECONDS
                )
                self._send_bytes(
                    200,
                    "text/html; charset=utf-8",
                    _render_index_html(self.state.csrf_token, sidecar_mode=True),
                    extra_headers={"Set-Cookie": cookie_hdr},
                )
                return

            if has_valid_cookie and (
                not token_vals
                or constant_time_equal(token_vals[0], self.state.bootstrap_token)
                or self.state.verify_owner_token(token_vals[0])
            ):
                cookie_val = self.state.create_session_cookie_value()
                cookie_hdr = "{}={}; Max-Age={}; HttpOnly; SameSite=Strict; Path=/".format(
                    SESSION_COOKIE_NAME, cookie_val, SESSION_TTL_SECONDS
                )
                self._send_bytes(
                    200,
                    "text/html; charset=utf-8",
                    _render_index_html(self.state.csrf_token, sidecar_mode=False),
                    extra_headers={"Set-Cookie": cookie_hdr},
                )
                return
            if token_vals and (
                self.state.consume_bootstrap_token(token_vals[0])
                or self.state.verify_owner_token(token_vals[0])
            ):
                cookie_val = self.state.create_session_cookie_value()
                cookie_hdr = "{}={}; Max-Age={}; HttpOnly; SameSite=Strict; Path=/".format(
                    SESSION_COOKIE_NAME, cookie_val, SESSION_TTL_SECONDS
                )
                self._send_bytes(
                    200,
                    "text/html; charset=utf-8",
                    _render_index_html(self.state.csrf_token, sidecar_mode=False),
                    extra_headers={"Set-Cookie": cookie_hdr},
                )
                return
            self._send_bytes(401, "text/html; charset=utf-8", _unauthorized_html())
            return

        if path == "/preload.js" and self.state.sidecar_mode:
            preload_path = self.state.preload_js_path
            if preload_path is not None and preload_path.is_file():
                self._send_bytes(200, "application/javascript; charset=utf-8", preload_path.read_bytes())
            else:
                self._send_bytes(200, "application/javascript; charset=utf-8", b"// agy-profiles sidecar bridge\n")
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
        if path.startswith("/fonts/"):
            self._serve_font_asset(path)
            return

        if not path.startswith("/api/"):
            self._send_json(404, ToolError("not_found", "Route not found.", http_status=404).to_dict())
            return

        if not self._authenticate_api_request(require_origin=False):
            return

        try:
            if path == "/api/state":
                res = call_tool("profile_list", {}, self.state.ctx)
                res["server"] = {
                    "version": __version__,
                    "origin": self.state.expected_origin,
                    "sidecar_mode": self.state.sidecar_mode,
                }
                self._send_json(200, res)
                return
            if path == "/api/doctor":
                self._send_json(200, call_tool("system_doctor", {}, self.state.ctx))
                return
            if path == "/api/handoff":
                qs = parse_qs(parsed.query)
                raw_limit = (qs.get("limit") or ["10"])[0]
                raw_source = (qs.get("source") or ["host"])[0]
                self._send_json(
                    200,
                    call_tool("host_handoff", {"limit": raw_limit, "source": raw_source}, self.state.ctx),
                )
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

    def _handle_sidecar_agentapi_post(self, action_path: str) -> None:
        if not self.state.sidecar_mode:
            self._send_json(404, ToolError("not_found", "Route not found.", http_status=404).to_dict())
            return
        if self.state.sidecar_ui_token and not (
            self._has_valid_sidecar_token() or self.state.verify_session_cookie_header(self.headers.get("Cookie"))
        ):
            self._send_json(401, {"error": "unauthorized"})
            return
        if not self._check_mutation_origin():
            return
        body = self._read_json_body()
        if body is None:
            return
        exe = os.environ.get("ANTIGRAVITY_AGENTAPI_EXE", "").strip()
        cmd: Optional[list[str]] = None
        if exe and Path(exe).exists():
            cmd = [exe, "agentapi"]
        else:
            agentapi_bin = shutil.which("agentapi")
            if agentapi_bin:
                cmd = [agentapi_bin]
        if cmd is None:
            self._send_json(503, {"error": "agentapi executable unavailable"})
            return
        env = os.environ.copy()
        if body.get("projectId"):
            env["ANTIGRAVITY_PROJECT_ID"] = str(body["projectId"])
        if action_path == "/_sidecar/send-message":
            args = ["send-message"]
            if body.get("title"):
                args.extend(["--title", str(body["title"])])
            args.extend([str(body.get("conversationId") or ""), str(body.get("message") or "")])
        elif action_path == "/_sidecar/new-conversation":
            args = ["new-conversation", "--model", str(body.get("model") or "flash"), str(body.get("message") or "")]
        elif action_path == "/_sidecar/get-conversation-metadata":
            args = ["get-conversation-metadata", str(body.get("conversationId") or "")]
        else:
            self._send_json(404, {"error": "Not found"})
            return
        try:
            proc = subprocess.run(
                cmd + args,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if proc.returncode != 0:
                self._send_json(500, {"error": proc.stderr.strip() or proc.stdout.strip() or "agentapi error"})
                return
            out_txt = proc.stdout.strip()
            self._send_json(200, json.loads(out_txt) if out_txt else {})
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            self._send_json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        if not self._check_host_or_reject():
            return
        parsed = urlparse(self.path)
        if parsed.path.startswith("/_sidecar/"):
            self._handle_sidecar_agentapi_post(parsed.path)
            return
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
            if parts == ["api", "heal"]:
                scope = str(body.get("scope") or "all")
                target = str(body.get("target") or "all")
                deep = bool(body.get("deep", False))
                try:
                    call_tool("host_handoff", {"limit": 15, "source": "host"}, self.state.ctx)
                except ToolError:
                    pass
                res = heal_electron_compositor(
                    scope=scope,
                    target=target,
                    deep=deep,
                    root=self.state.ctx.root,
                    real_home=self.state.ctx.real_home,
                )
                self._send_json(200, res)
                return
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
                if action == "rename":
                    payload = dict(body)
                    payload["source"] = name
                    self._send_json(200, call_tool("profile_rename", payload, self.state.ctx))
                    return
                if action == "launcher":
                    payload = dict(body)
                    op = payload.pop("action", "build")
                    payload["name"] = name
                    tool_name = "launcher_remove" if op == "remove" else "launcher_build"
                    self._send_json(200, call_tool(tool_name, payload, self.state.ctx))
                    return
                if action == "sync":
                    payload = dict(body)
                    payload["name"] = name
                    self._send_json(200, call_tool("profile_sync", payload, self.state.ctx))
                    return
                if action == "switch":
                    payload = dict(body)
                    payload["name"] = name
                    self._send_json(200, call_tool("profile_switch", payload, self.state.ctx))
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
    sidecar_mode: bool = False,
) -> DualStackLoopbackHTTPServer:
    """Create a hardened loopback HTTP server bound to host:port (or sidecar port in sidecar mode)."""
    bind_host = validate_bind_host("127.0.0.1" if sidecar_mode else host)
    actual_port = port
    sidecar_ui_token = ""
    preload_path: Optional[Path] = None
    if sidecar_mode:
        env_port = os.environ.get("ANTIGRAVITY_SIDECAR_WEB_PORT", "").strip()
        if env_port:
            try:
                actual_port = int(env_port)
            except ValueError:
                pass
        sidecar_ui_token = os.environ.get("ANTIGRAVITY_SIDECAR_UI_TOKEN", "").strip()
        env_preload = os.environ.get("AGY_SIDECAR_PRELOAD_JS", "").strip()
        if env_preload:
            preload_path = Path(env_preload).expanduser()
        else:
            default_preload = Path.home() / ".gemini" / "antigravity" / "lib" / "node_modules" / "sidecar_sdk" / "preload.js"
            if default_preload.is_file():
                preload_path = default_preload

    sec_state = ServerSecurityState(
        ctx=ctx,
        host=bind_host,
        port=actual_port,
        sidecar_mode=sidecar_mode,
        sidecar_ui_token=sidecar_ui_token,
        preload_js_path=preload_path,
    )
    try:
        return DualStackLoopbackHTTPServer((bind_host, actual_port), HardenedWebHandler, sec_state)
    except OSError:
        if actual_port == 0 or sidecar_mode:
            raise
        # Fall back cleanly to an ephemeral loopback port if default port is occupied.
        return DualStackLoopbackHTTPServer((bind_host, 0), HardenedWebHandler, sec_state)


def run_web_server_in_thread(
    ctx: RuntimeContext,
    host: str = "127.0.0.1",
    port: int = 0,
    sidecar_mode: bool = False,
) -> Tuple[DualStackLoopbackHTTPServer, threading.Thread]:
    """Start loopback web server in a background daemon thread for tests or embedding."""
    httpd = create_web_server(ctx, host=host, port=port, sidecar_mode=sidecar_mode)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread
