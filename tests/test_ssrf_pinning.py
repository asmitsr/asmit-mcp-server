"""Tests for the DNS-pinned HEAD fetch (SSRF rebinding fix).

The pinned path resolves a hostname once, validates every address,
and connects to one of those validated addresses only. These tests
mock DNS (socket.getaddrinfo) and the socket/HTTP layers, so they run
offline, and they assert WHICH IP reached socket.create_connection —
"blocked" alone would not prove pinning.
"""

import json
import os
import socket
import ssl
import sys
import unittest
from typing import ClassVar
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from asmit_mcp.core.http import TIMEOUT_SECONDS, USER_AGENT
from asmit_mcp.core.ssrf import SSRFBlockedError, fetch_head_pinned
from asmit_mcp.tools.utility import check_url_status

# Saved before any test patches ssl.create_default_context, so the
# verified-context test can build a REAL default context.
_real_create_default_context = ssl.create_default_context


def parse(result):
    return json.loads(result)


PUBLIC_IP = "93.184.216.34"
PUBLIC_IP_2 = "93.184.216.35"
PRIVATE_IP = "127.0.0.1"
IPV6_PUBLIC = "2606:4700:4700::1111"


def addrinfo(ip, family=socket.AF_INET, port=80):
    return [(family, socket.SOCK_STREAM, 6, "", (ip, port))]


class FakeResponse:
    """Minimal http.client.HTTPResponse stand-in."""

    def __init__(self, status, location=None):
        self.status = status
        self._location = location

    def getheader(self, name, default=None):
        if name.lower() == "location":
            return self._location if self._location is not None else default
        return default

    def read(self, *args):
        return b""


class FakeConnection:
    """http.client connection stand-in serving queued responses."""

    responses: ClassVar[list] = []
    instances: ClassVar[list] = []

    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.requests = []
        self.closed = False
        FakeConnection.instances.append(self)

    def request(self, method, url, body=None, headers=None):
        self.requests.append((method, url, headers or {}))

    def getresponse(self):
        resp = FakeConnection.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp

    def close(self):
        self.closed = True


class PinnedFetchTestBase(unittest.TestCase):
    def setUp(self):
        FakeConnection.responses = []
        FakeConnection.instances = []
        self.sock = mock.MagicMock(name="sock")
        self.ssl_sock = mock.MagicMock(name="ssl_sock")
        self.ssl_context = mock.MagicMock(name="ssl_context")
        self.ssl_context.wrap_socket.return_value = self.ssl_sock
        self._patchers = [
            mock.patch("asmit_mcp.core.ssrf.socket.getaddrinfo"),
            mock.patch("asmit_mcp.core.ssrf.socket.create_connection",
                       return_value=self.sock),
            mock.patch("asmit_mcp.core.ssrf.http.client.HTTPConnection",
                       FakeConnection),
            mock.patch("asmit_mcp.core.ssrf.http.client.HTTPSConnection",
                       FakeConnection),
            mock.patch("asmit_mcp.core.ssrf.ssl.create_default_context",
                       return_value=self.ssl_context),
        ]
        self.mock_getaddrinfo = self._patchers[0].start()
        self.mock_create_conn = self._patchers[1].start()
        for patcher in self._patchers[2:]:
            patcher.start()
        # Default DNS: every host resolves to one public IPv4 address.
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *args, **kwargs: addrinfo(PUBLIC_IP))

    def tearDown(self):
        for patcher in reversed(self._patchers):
            patcher.stop()

    def connected_ips(self):
        return [call.args[0][0]
                for call in self.mock_create_conn.call_args_list]


class TestRebinding(PinnedFetchTestBase):
    def test_rebinding_second_resolution_ignored(self):
        # TOCTOU: DNS answers public first, then flips to 127.0.0.1.
        # The pinned connection must still use the validated public IP.
        calls = {"n": 0}

        def _dns(host, port, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return addrinfo(PUBLIC_IP)
            return addrinfo(PRIVATE_IP)

        self.mock_getaddrinfo.side_effect = _dns

        def _connect(address, timeout=None):
            # Simulate a connect-time re-resolution (what urllib did):
            # the answer has flipped, but the pinned IP must win.
            self.mock_getaddrinfo("example.com", None)
            return self.sock

        self.mock_create_conn.side_effect = _connect
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://example.com/"))
        self.assertEqual(self.connected_ips(), [PUBLIC_IP])
        self.assertNotIn(PRIVATE_IP, self.connected_ips())
        self.assertGreaterEqual(calls["n"], 2)
        conn = FakeConnection.instances[0]
        self.assertEqual(conn.requests[0][2]["Host"], "example.com")
        self.assertEqual(conn.requests[0][2]["User-Agent"], USER_AGENT)
        self.assertIs(conn.sock, self.sock)

    def test_multiple_ips_one_private_blocks_whole_request(self):
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo(PUBLIC_IP)
            + addrinfo("10.0.0.5"))
        with self.assertRaises(SSRFBlockedError):
            fetch_head_pinned("http://example.com/")
        self.mock_create_conn.assert_not_called()
        # Same result when the private address comes first.
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo("10.0.0.5")
            + addrinfo(PUBLIC_IP))
        with self.assertRaises(SSRFBlockedError):
            fetch_head_pinned("http://example.com/")
        self.mock_create_conn.assert_not_called()

    def test_connection_falls_back_to_next_validated_ip(self):
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo(PUBLIC_IP)
            + addrinfo(PUBLIC_IP_2))

        def _connect(address, timeout=None):
            if address[0] == PUBLIC_IP:
                raise ConnectionRefusedError("refused")
            return self.sock

        self.mock_create_conn.side_effect = _connect
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://example.com/"))
        self.assertEqual(self.connected_ips(), [PUBLIC_IP, PUBLIC_IP_2])


class TestIPv6(PinnedFetchTestBase):
    def test_ipv6_global_address_is_pinned(self):
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo(
                IPV6_PUBLIC, family=socket.AF_INET6))
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://example.com/"))
        self.assertEqual(self.connected_ips(), [IPV6_PUBLIC])

    def test_ipv4_mapped_private_addresses_blocked(self):
        for mapped in ("::ffff:127.0.0.1", "::ffff:10.0.0.1",
                       "::ffff:169.254.169.254"):
            with self.subTest(mapped=mapped):
                def _dns(host, port, *a, m=mapped, **k):
                    return addrinfo(m, family=socket.AF_INET6)

                self.mock_getaddrinfo.side_effect = _dns
                with self.assertRaises(SSRFBlockedError):
                    fetch_head_pinned("http://example.com/")
                self.mock_create_conn.assert_not_called()

    def test_ipv4_mapped_public_address_allowed(self):
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo(
                "::ffff:93.184.216.34", family=socket.AF_INET6))
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://example.com/"))
        self.assertEqual(self.connected_ips(), ["::ffff:93.184.216.34"])


class TestHTTPS(PinnedFetchTestBase):
    def test_host_header_with_port_and_sni_uses_hostname(self):
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("https://example.com:8443/")
        self.assertEqual((status, final_url),
                         (200, "https://example.com:8443/"))
        conn = FakeConnection.instances[0]
        self.assertEqual(conn.requests[0][2]["Host"], "example.com:8443")
        self.assertIs(conn.sock, self.ssl_sock)
        self.ssl_context.wrap_socket.assert_called_once_with(
            self.sock, server_hostname="example.com")
        self.assertEqual(self.mock_create_conn.call_args_list[0].args[0],
                         (PUBLIC_IP, 8443))

    def test_host_header_default_port_has_no_port(self):
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("https://example.com/")
        self.assertEqual((status, final_url), (200, "https://example.com/"))
        conn = FakeConnection.instances[0]
        self.assertEqual(conn.requests[0][2]["Host"], "example.com")
        self.ssl_context.wrap_socket.assert_called_once_with(
            self.sock, server_hostname="example.com")

    def test_https_uses_verified_default_context(self):
        # The REAL default context (not a mock): verify + check_hostname
        # must be on, and wrap must get the original hostname as SNI.
        real_ctx = _real_create_default_context()
        FakeConnection.responses = [FakeResponse(200)]
        with mock.patch(
                "asmit_mcp.core.ssrf.ssl.create_default_context",
                return_value=real_ctx), mock.patch.object(
                    real_ctx, "wrap_socket",
                    return_value=self.ssl_sock) as mock_wrap:
            status, final_url = fetch_head_pinned(
                "https://example.com/")
        self.assertEqual((status, final_url), (200, "https://example.com/"))
        self.assertTrue(real_ctx.check_hostname)
        self.assertEqual(real_ctx.verify_mode, ssl.CERT_REQUIRED)
        mock_wrap.assert_called_once_with(
            self.sock, server_hostname="example.com")


class TestTimeouts(PinnedFetchTestBase):
    def test_connect_and_read_timeout_default_15s(self):
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://example.com/"))
        self.mock_create_conn.assert_called_once_with(
            (PUBLIC_IP, 80), timeout=TIMEOUT_SECONDS)
        # The read timeout is set explicitly on the socket, because
        # http.client never touches a pre-connected socket's timeout.
        self.sock.settimeout.assert_called_once_with(TIMEOUT_SECONDS)

    def test_https_read_timeout_set_on_wrapped_socket(self):
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("https://example.com/")
        self.assertEqual((status, final_url), (200, "https://example.com/"))
        self.ssl_sock.settimeout.assert_called_once_with(TIMEOUT_SECONDS)

    def test_per_hop_timeout_capped_by_remaining_deadline(self):
        # 5s left in the overall budget: the hop gets 5s, not 15s.
        with mock.patch("asmit_mcp.core.ssrf.time.monotonic",
                        side_effect=[1000.0, 1055.0]):
            FakeConnection.responses = [FakeResponse(200)]
            status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://example.com/"))
        self.mock_create_conn.assert_called_once_with(
            (PUBLIC_IP, 80), timeout=5)
        self.sock.settimeout.assert_called_once_with(5)

    def test_overall_deadline_exceeded_before_next_hop(self):
        with mock.patch("asmit_mcp.core.ssrf.time.monotonic",
                        side_effect=[1000.0, 1061.0]), \
                self.assertRaises(TimeoutError):
            fetch_head_pinned("http://example.com/")
        self.mock_create_conn.assert_not_called()

    def test_check_url_status_deadline_is_unreachable(self):
        with mock.patch("asmit_mcp.core.ssrf.time.monotonic",
                        side_effect=[1000.0, 1061.0]):
            result = parse(check_url_status("http://example.com/"))
        self.assertTrue(result["ok"])
        self.assertFalse(result["reachable"])
        self.assertIn("timed out", result["error"])


class TestSocketClose(PinnedFetchTestBase):
    def test_socket_closed_on_success(self):
        FakeConnection.responses = [FakeResponse(200)]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://example.com/"))
        self.assertTrue(FakeConnection.instances[0].closed)

    def test_socket_closed_when_response_fails(self):
        FakeConnection.responses = [ConnectionResetError("reset")]
        with self.assertRaises(ConnectionResetError):
            fetch_head_pinned("http://example.com/")
        self.assertTrue(FakeConnection.instances[0].closed)

    def test_socket_closed_when_tls_wrap_fails(self):
        self.ssl_context.wrap_socket.side_effect = ValueError(
            "bad hostname")
        with self.assertRaises(ValueError):
            fetch_head_pinned("https://example.com/")
        # conn never existed, so the raw socket is closed instead.
        self.sock.close.assert_called_once_with()

    def test_redirect_hops_each_close_their_socket(self):
        dns = {"example.com": PUBLIC_IP, "other.example": PUBLIC_IP_2}
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo(dns[host]))
        FakeConnection.responses = [
            FakeResponse(302, "http://other.example/"),
            FakeResponse(200),
        ]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://other.example/"))
        self.assertEqual(len(FakeConnection.instances), 2)
        self.assertTrue(
            all(conn.closed for conn in FakeConnection.instances))


class TestRedirects(PinnedFetchTestBase):
    def test_redirect_chain_repins_each_hop(self):
        dns = {"example.com": PUBLIC_IP, "other.example": PUBLIC_IP_2}
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo(dns[host]))
        FakeConnection.responses = [
            FakeResponse(302, "http://other.example/"),
            FakeResponse(200),
        ]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://other.example/"))
        self.assertEqual(self.connected_ips(), [PUBLIC_IP, PUBLIC_IP_2])
        second = FakeConnection.instances[1]
        self.assertEqual(second.requests[0][2]["Host"], "other.example")

    def test_redirect_to_private_is_blocked(self):
        dns = {"example.com": PUBLIC_IP, "127.0.0.1": PRIVATE_IP}
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo(dns[host]))
        FakeConnection.responses = [FakeResponse(302, "http://127.0.0.1/")]
        with self.assertRaises(SSRFBlockedError):
            fetch_head_pinned("http://example.com/")
        self.assertEqual(self.connected_ips(), [PUBLIC_IP])

    def test_check_url_status_redirect_to_private(self):
        dns = {"example.com": PUBLIC_IP, "127.0.0.1": PRIVATE_IP}
        self.mock_getaddrinfo.side_effect = (
            lambda host, port, *a, **k: addrinfo(dns[host]))
        FakeConnection.responses = [FakeResponse(302, "http://127.0.0.1/")]
        result = parse(check_url_status("http://example.com/"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error_code"], "SSRF_BLOCKED")
        self.assertEqual(result["error"],
                         "blocked: redirect target is not a public address")
        self.assertEqual(self.connected_ips(), [PUBLIC_IP])

    def test_sixth_redirect_matches_urllib(self):
        # urllib follows 5 redirects; the 6th raises HTTPError 302,
        # which check_url_status turns into reachable True, status 302.
        hosts = ["a.example", "b.example", "c.example", "d.example",
                 "e.example", "f.example", "g.example"]
        FakeConnection.responses = [
            FakeResponse(302, f"http://{hosts[i + 1]}/")
            for i in range(6)
        ]
        result = parse(check_url_status("http://a.example/"))
        self.assertTrue(result["ok"])
        self.assertTrue(result["reachable"])
        self.assertEqual(result["status"], 302)
        self.assertEqual(result["final_url"], "http://f.example/")
        self.assertEqual(len(self.mock_create_conn.call_args_list), 6)

    def test_relative_redirect_is_joined(self):
        FakeConnection.responses = [FakeResponse(302, "/next"),
                                    FakeResponse(200)]
        status, final_url = fetch_head_pinned("http://example.com/")
        self.assertEqual((status, final_url), (200, "http://example.com/next"))
        self.assertEqual(FakeConnection.instances[1].requests[0][1], "/next")

    def test_https_to_http_downgrade_is_followed(self):
        FakeConnection.responses = [
            FakeResponse(302, "http://example.com/plain"),
            FakeResponse(200),
        ]
        status, final_url = fetch_head_pinned("https://example.com/")
        self.assertEqual((status, final_url),
                         (200, "http://example.com/plain"))
        # Only the HTTPS hop wrapped a socket; the HTTP hop did not.
        self.assertEqual(self.ssl_context.wrap_socket.call_count, 1)


class TestCheckUrlStatusWiring(PinnedFetchTestBase):
    def test_check_url_status_uses_pinned_path(self):
        FakeConnection.responses = [FakeResponse(200)]
        with mock.patch("urllib.request.build_opener") as mock_opener:
            result = parse(check_url_status("http://example.com/"))
        mock_opener.assert_not_called()
        self.assertTrue(result["ok"])
        self.assertTrue(result["reachable"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["final_url"], "http://example.com/")
        # The pinned path connects to the validated IP; the old urllib
        # path would have passed the hostname to create_connection.
        self.assertEqual(self.connected_ips(), [PUBLIC_IP])
        for call in self.mock_create_conn.call_args_list:
            self.assertNotEqual(call.args[0][0], "example.com")

    def test_connection_failure_is_unreachable_not_error(self):
        self.mock_create_conn.side_effect = ConnectionRefusedError(
            "refused")
        result = parse(check_url_status("http://example.com/"))
        self.assertTrue(result["ok"])
        self.assertFalse(result["reachable"])
        self.assertIn("refused", result["error"])


if __name__ == "__main__":
    unittest.main()
