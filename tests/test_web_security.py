"""Integration tests for loopback-only web server CSRF, Host, Origin, and CSP enforcement."""

from __future__ import annotations

import http.client
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agy_profiles.daemon import (
    WATCHDOG_LABEL,
    WEB_LABEL,
    acquire_watchdog_lock,
    install_daemons,
    uninstall_daemons,
)
from agy_profiles.errors import ToolError
from agy_profiles.tools import RuntimeContext
from agy_profiles.web_server import (
    BOOTSTRAP_GRACE_SECONDS,
    SESSION_TTL_SECONDS,
    run_web_server_in_thread,
    validate_bind_host,
)


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
        state_payload = json.loads(body)
        self.assertEqual(state_payload["profiles"], [])
        self.assertIn("auto_recovery", state_payload)

        # Recover requires Origin and CSRF, and returns 200 JSON when authenticated
        status, _, _ = self._request(
            "POST",
            "/api/recover",
            headers={"Cookie": cookie, "Origin": self.sec.expected_origin},
            body={"dry_run": True},
        )
        self.assertEqual(status, 403)
        status, _, body = self._request(
            "POST",
            "/api/recover",
            headers=auth_headers,
            body={"scope": "all", "dry_run": True},
        )
        self.assertEqual(status, 200)
        recover_payload = json.loads(body)
        self.assertTrue(recover_payload["dry_run"])
        self.assertIn("stalled_total", recover_payload)
        self.assertIn("evidence", recover_payload)

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

        status, _, body = self._request("GET", "/api/handoff?limit=5", headers={"Cookie": cookie, "X-AGY-CSRF": csrf})
        self.assertEqual(status, 200)
        handoff_payload = json.loads(body)
        self.assertIn("available", handoff_payload)
        self.assertIn("conversations", handoff_payload)

        status, _, _ = self._request(
            "POST",
            "/api/profiles/alpha/sync",
            headers={"Cookie": cookie, "Origin": self.sec.expected_origin},
            body={"include_sidecars": False, "include_handoff": False},
        )
        self.assertEqual(status, 403)

        status, _, body = self._request(
            "POST",
            "/api/profiles/alpha/sync",
            headers={"Cookie": cookie, "X-AGY-CSRF": csrf, "Origin": self.sec.expected_origin},
            body={"automations_mode": "paused", "include_handoff": False},
        )
        self.assertEqual(status, 200)
        sync_payload = json.loads(body)
        self.assertIn("sync", sync_payload)
        self.assertEqual(sync_payload["manifest"]["name"], "alpha")
        self.assertEqual(sync_payload["sync"]["automations_mode"], "paused")

        # Bidirectional handoff query parameter
        status, _, body = self._request(
            "GET",
            "/api/handoff?limit=5&source=alpha",
            headers={"Cookie": cookie, "X-AGY-CSRF": csrf},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["source"], "alpha")

        # Switch requires CSRF and returns 200 with launch=False
        status, _, _ = self._request(
            "POST",
            "/api/profiles/alpha/switch",
            headers={"Cookie": cookie, "Origin": self.sec.expected_origin},
            body={"launch": False},
        )
        self.assertEqual(status, 403)
        status, _, body = self._request(
            "POST",
            "/api/profiles/alpha/switch",
            headers=auth_headers,
            body={"launch": False, "automations_mode": "active"},
        )
        self.assertEqual(status, 200)
        switch_payload = json.loads(body)
        self.assertEqual(switch_payload["switch"]["automations_mode"], "active")

        # Rename requires CSRF and succeeds cleanly
        status, _, _ = self._request(
            "POST",
            "/api/profiles/beta/rename",
            headers={"Cookie": cookie, "Origin": self.sec.expected_origin},
            body={"target": "beta-renamed"},
        )
        self.assertEqual(status, 403)
        status, _, body = self._request(
            "POST",
            "/api/profiles/beta/rename",
            headers=auth_headers,
            body={"target": "beta-renamed", "label": "Beta Renamed"},
        )
        self.assertEqual(status, 200)
        renamed_payload = json.loads(body)
        self.assertEqual(renamed_payload["manifest"]["name"], "beta-renamed")
        self.assertEqual(renamed_payload["renamed_from"], "beta")

        # Delete
        status, _, body = self._request(
            "DELETE",
            "/api/profiles/beta-renamed",
            headers=auth_headers,
            body={"force_stop": False},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["deleted"])

    def test_session_ttl_and_bootstrap_grace_expiry(self) -> None:
        now_epoch = 1_700_000_000
        cookie_val = self.sec.create_session_cookie_value(now_epoch=now_epoch)
        hdr = "__agy_session=" + cookie_val
        self.assertTrue(self.sec.verify_session_cookie_header(hdr, now_epoch=now_epoch + 60))
        self.assertFalse(
            self.sec.verify_session_cookie_header(hdr, now_epoch=now_epoch + SESSION_TTL_SECONDS + 10)
        )

        self.assertTrue(self.sec.consume_bootstrap_token(self.sec.bootstrap_token, now_mono=100.0))
        self.assertTrue(
            self.sec.consume_bootstrap_token(
                self.sec.bootstrap_token,
                now_mono=100.0 + BOOTSTRAP_GRACE_SECONDS - 1.0,
            )
        )
        self.assertFalse(
            self.sec.consume_bootstrap_token(
                self.sec.bootstrap_token,
                now_mono=100.0 + BOOTSTRAP_GRACE_SECONDS + 1.0,
            )
        )

    def test_sidecar_mode_framing_and_token_auth(self) -> None:
        sidecar_httpd, sidecar_thread = run_web_server_in_thread(
            self.ctx,
            host="127.0.0.1",
            port=0,
            sidecar_mode=True,
        )
        try:
            sidecar_httpd.security_state.sidecar_ui_token = "sc_tok_test_123"
            sc_sec = sidecar_httpd.security_state
            sc_ip, sc_port = sidecar_httpd.server_address[:2]

            conn = http.client.HTTPConnection(sc_ip, sc_port, timeout=5)
            conn.request("GET", "/?token=sc_tok_test_123&conversationId=conv-1")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8")
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertIsNone(resp.headers.get("X-Frame-Options"))
            self.assertIn("frame-ancestors 'self'", resp.headers.get("Content-Security-Policy", ""))
            self.assertIn('/preload.js', body)

            # In sidecar mode, X-Sidecar-Token + X-AGY-CSRF authenticates API even without session Cookie.
            conn = http.client.HTTPConnection(sc_ip, sc_port, timeout=5)
            conn.request(
                "GET",
                "/api/state",
                headers={
                    "Host": "localhost:{}".format(sc_port),
                    "X-Sidecar-Token": "sc_tok_test_123",
                    "X-AGY-CSRF": sc_sec.csrf_token,
                },
            )
            api_resp = conn.getresponse()
            api_body = api_resp.read()
            conn.close()
            self.assertEqual(api_resp.status, 200)
            self.assertTrue(json.loads(api_body)["server"]["sidecar_mode"])
        finally:
            sidecar_httpd.shutdown()
            sidecar_httpd.server_close()
            sidecar_thread.join(timeout=2)

    def test_font_route_containment_and_mime(self) -> None:
        status, headers, body = self._request("GET", "/fonts/fustat-latin-wght-normal.woff2")
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

    def test_persistent_secrets_survive_server_restart_and_owner_token_reusable(self) -> None:
        self.assertGreaterEqual(SESSION_TTL_SECONDS, 365 * 86400)
        owner_tok = self.sec.owner_token
        self.assertTrue(len(owner_tok) >= 32)

        status, headers, _ = self._request("GET", "/?token=" + owner_tok)
        self.assertEqual(status, 200)
        cookie_pair = headers.get("Set-Cookie", "").split(";", 1)[0]
        csrf = self.sec.csrf_token

        # Owner token remains reusable across subsequent sessions/reloads.
        status2, _, _ = self._request("GET", "/?token=" + owner_tok)
        self.assertEqual(status2, 200)

        # Restart a brand-new server instance over the same profile root and verify existing browser cookie still works.
        restarted_httpd, restarted_thread = run_web_server_in_thread(self.ctx, host="127.0.0.1", port=0)
        try:
            r_ip, r_port = restarted_httpd.server_address[:2]
            conn = http.client.HTTPConnection(r_ip, r_port, timeout=5)
            conn.request("GET", "/", headers={"Cookie": cookie_pair})
            r_resp = conn.getresponse()
            r_resp.read()
            renewed_cookie = r_resp.headers.get("Set-Cookie", "")
            conn.close()
            self.assertEqual(r_resp.status, 200)
            self.assertIn("__agy_session=", renewed_cookie)

            conn2 = http.client.HTTPConnection(r_ip, r_port, timeout=5)
            conn2.request("GET", "/api/state", headers={"Cookie": cookie_pair, "X-AGY-CSRF": csrf})
            api_resp = conn2.getresponse()
            api_resp.read()
            conn2.close()
            self.assertEqual(api_resp.status, 200)
        finally:
            restarted_httpd.shutdown()
            restarted_httpd.server_close()
            restarted_thread.join(timeout=2)

    def test_daemon_plist_generation_and_watchdog_single_instance_lock(self) -> None:
        import plistlib

        res = install_daemons(self.ctx, port=47920, interval_sec=5.0, prevent_sleep=True, open_browser=False, dry_run=True)
        self.assertTrue(res["installed"])
        wd_plist_path = Path(res["watchdog_plist"])
        web_plist_path = Path(res["web_plist"])
        self.assertTrue(wd_plist_path.is_file())
        self.assertTrue(web_plist_path.is_file())

        wd_data = plistlib.loads(wd_plist_path.read_bytes())
        self.assertEqual(wd_data["Label"], WATCHDOG_LABEL)
        self.assertTrue(wd_data["RunAtLoad"])
        self.assertTrue(wd_data["KeepAlive"])
        if Path("/usr/bin/caffeinate").is_file():
            self.assertEqual(wd_data["ProgramArguments"][:2], ["/usr/bin/caffeinate", "-i"])

        web_data = plistlib.loads(web_plist_path.read_bytes())
        self.assertEqual(web_data["Label"], WEB_LABEL)
        self.assertTrue(web_data["RunAtLoad"])
        self.assertTrue(web_data["KeepAlive"])

        fh1 = acquire_watchdog_lock(self.root)
        self.assertIsNotNone(fh1)
        try:
            fh2 = acquire_watchdog_lock(self.root)
            self.assertIsNone(fh2)
        finally:
            fh1.close()

        un_res = uninstall_daemons(self.ctx, dry_run=False)
        self.assertEqual(len(un_res["removed_plists"]), 2)


if __name__ == "__main__":
    unittest.main()
