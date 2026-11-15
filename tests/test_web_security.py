"""Integration tests for loopback-only web server CSRF, Host, Origin, and CSP enforcement."""

from __future__ import annotations

import http.client
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agy_profiles.errors import ToolError
from agy_profiles.tools import RuntimeContext
from agy_profiles.web_server import run_web_server_in_thread, validate_bind_host


class WebSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "profiles"
        self.root.mkdir(mode=0o700)
        self.fake_home = Path(self.tmp.name).resolve() / "fake-home"
        self.fake_home.mkdir(mode=0o700)
        self.ctx = RuntimeContext(root=self.root, real_home=self.fake_home)
        self.httpd, self.thread = run_web_server_in_thread(self.ctx, host="127.0.0.1", port=0)
        self.sec = self.httpd.security_state
        self.host_ip, self.port = self.httpd.server_address[:2]

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def _request(
        self,
        method: str,
        path: str,
        headers: dict | None = None,
        body: dict | None = None,
    ) -> tuple[int, http.client.HTTPMessage, bytes]:
        conn = http.client.HTTPConnection(self.host_ip, self.port, timeout=5)
        try:
            hdrs = dict(headers or {})
            payload = None
            if body is not None:
                payload = json.dumps(body).encode("utf-8")
                hdrs.setdefault("Content-Type", "application/json")
            conn.request(method, path, body=payload, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, resp.headers, data
        finally:
            conn.close()

    def _authenticate(self) -> tuple[str, str]:
        status, headers, body = self._request("GET", "/?token=" + self.sec.bootstrap_token)
        self.assertEqual(status, 200)
        set_cookie = headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        cookie_pair = set_cookie.split(";", 1)[0]

        csp = headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("font-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")

        html = body.decode("utf-8")
        self.assertIn(self.sec.csrf_token, html)
        return cookie_pair, self.sec.csrf_token

    def test_loopback_only_bind_validation(self) -> None:
        self.assertEqual(validate_bind_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_bind_host("::1"), "::1")
        for unsafe in ["localhost", "0.0.0.0", "::", "192.168.1.50", "10.0.0.2", "example.com"]:
            with self.assertRaises(ToolError):
                validate_bind_host(unsafe)

    def test_unauthenticated_and_wrong_host_and_bad_origin_rejected(self) -> None:
        status, _, _ = self._request("GET", "/")
        self.assertEqual(status, 401)

        status, _, _ = self._request("GET", "/?token=wrong-token")
        self.assertEqual(status, 401)

        cookie, csrf = self._authenticate()

        # DNS rebinding Host header rejected.
        status, _, _ = self._request(
            "GET",
            "/api/state",
            headers={"Host": "evil.com:{}".format(self.port), "Cookie": cookie, "X-AGY-CSRF": csrf},
        )
        self.assertEqual(status, 403)

        # Missing X-AGY-CSRF rejected on GET API.
        status, _, _ = self._request("GET", "/api/state", headers={"Cookie": cookie})
        self.assertEqual(status, 403)

        # Missing Origin rejected on POST.
        status, _, _ = self._request(
            "POST",
            "/api/profiles",
            headers={"Cookie": cookie, "X-AGY-CSRF": csrf},
            body={"name": "no-origin"},
        )
        self.assertEqual(status, 403)

        # Origin: null rejected on POST.
        status, _, _ = self._request(
            "POST",
            "/api/profiles",
            headers={"Cookie": cookie, "X-AGY-CSRF": csrf, "Origin": "null"},
            body={"name": "null-origin"},
        )
        self.assertEqual(status, 403)

        # Origin host mismatch (localhost vs 127.0.0.1) rejected on POST.
        status, _, _ = self._request(
            "POST",
            "/api/profiles",
            headers={
                "Cookie": cookie,
                "X-AGY-CSRF": csrf,
                "Origin": "http://localhost:{}".format(self.port),
            },
            body={"name": "localhost-origin"},
        )
        self.assertEqual(status, 403)

    def test_authenticated_crud_obligations_and_doctor(self) -> None:
        cookie, csrf = self._authenticate()
        auth_headers = {
            "Cookie": cookie,
            "X-AGY-CSRF": csrf,
            "Origin": self.sec.expected_origin,
        }

        status, _, body = self._request("GET", "/api/state", headers={"Cookie": cookie, "X-AGY-CSRF": csrf})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["profiles"], [])

        # Create
        status, _, body = self._request(
            "POST",
            "/api/profiles",
            headers=auth_headers,
            body={"name": "alpha", "label": "Alpha Workspace", "link_policy": "minimal"},
        )
        self.assertEqual(status, 201)
        created = json.loads(body)
        self.assertEqual(created["manifest"]["name"], "alpha")
        self.assertIn("evidence_id", created["evidence"])

        # Update
        status, _, body = self._request(
            "PATCH",
            "/api/profiles/alpha",
            headers=auth_headers,
            body={"link_policy": "none", "label": "Alpha Locked"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["manifest"]["link_policy"], "none")

        # Clone
        status, _, body = self._request(
            "POST",
            "/api/profiles/alpha/clone",
            headers=auth_headers,
            body={"target": "beta"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["manifest"]["name"], "beta")

        # Repair
        status, _, body = self._request(
            "POST",
            "/api/profiles/alpha/repair",
            headers=auth_headers,
            body={},
        )
        self.assertEqual(status, 200)

        # Obligations & Doctor
        status, _, body = self._request("GET", "/api/obligations", headers={"Cookie": cookie, "X-AGY-CSRF": csrf})
        self.assertEqual(status, 200)
        obl = json.loads(body)
        self.assertEqual(obl["summary"]["failed"], 0)
        self.assertGreaterEqual(obl["summary"]["closed"], 6)

        status, _, body = self._request("GET", "/api/doctor", headers={"Cookie": cookie, "X-AGY-CSRF": csrf})
        self.assertEqual(status, 200)
        self.assertIn("checks", json.loads(body))

        # Delete
        status, _, body = self._request(
            "DELETE",
            "/api/profiles/beta",
            headers=auth_headers,
            body={"force_stop": False},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["deleted"])

    def test_font_route_containment_and_mime(self) -> None:
        status, headers, body = self._request("GET", "/fonts/fraunces-latin-wght-normal.woff2")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "font/woff2")
        self.assertGreater(len(body), 1000)

        for bad_path in (
            "/fonts/../index.html",
            "/fonts/%2e%2e/app.js",
            "/fonts/missing.woff2",
        ):
            status, _, _ = self._request("GET", bad_path)
            self.assertEqual(status, 404, msg="Expected 404 for {}".format(bad_path))


if __name__ == "__main__":
    unittest.main()
