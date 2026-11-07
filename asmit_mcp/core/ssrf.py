"""SSRF protection for user-supplied URLs (used by check_url_status).

Only check_url_status takes a URL from the caller; every other tool
talks to fixed API hosts, so this is the only SSRF surface in the
server. The guard runs BEFORE any request is made, and again for
every redirect target.

Rules:
  - Scheme must be http or https; URLs carrying credentials are rejected.
  - The hostname must resolve, and EVERY resolved address must be
    globally routable (ip.is_global). That single rule blocks loopback,
    private, link-local (including cloud metadata 169.254.169.254),
    multicast, reserved and unspecified addresses, without maintaining
    a hand-written blocklist. IPv4-mapped IPv6 addresses are judged by
    the embedded IPv4 address too, so ::ffff:127.0.0.1 is blocked.
  - Resolved addresses are never echoed in error messages: an attacker
    probing internal hosts must not learn what resolved to what.
  - DNS rebinding is stopped by pinning: the hostname is resolved
    once per hop, every address is validated, and the socket connects
    to one of those validated addresses only — the connection never
    re-resolves the hostname, so a changed answer cannot redirect it
    to a private address. For HTTPS, SNI and certificate verification
    still use the original hostname, and the Host header carries it.
  - Redirects are followed manually (fetch_head_pinned), at most 5,
    each hop re-resolved and re-validated the same way.

This guard does not make a URL "safe" in general — it only stops the
server from being used to reach non-public addresses. The target server
itself is still untrusted.

Environment note: http.client ignores HTTP_PROXY/HTTPS_PROXY, so the
pinned connection goes direct and never uses a proxy. On networks
where local DNS is intercepted (for example a VM whose resolver maps
every public hostname to a synthetic reserved address such as
198.18.x.x for an egress proxy), this guard is conservative — it
blocks the URL instead of fetching it, because the locally resolved
address is not globally routable. It never fails open: a private
address is never allowed, even if that means a public URL is blocked
in such an environment. On a normal machine with direct DNS, public
URLs resolve to real global addresses and pass.
"""

import http.client
import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

from asmit_mcp.core.errors import ValidationError
from asmit_mcp.core.http import TIMEOUT_SECONDS, USER_AGENT


class SSRFBlockedError(Exception):
    """Raised when a URL is blocked by the SSRF guard."""


def _is_public(ip):
    """True only for a globally routable address.

    ip.is_global already rejects loopback, private, link-local,
    multicast, reserved and unspecified addresses. IPv4-mapped IPv6
    addresses are additionally judged by the embedded IPv4 address,
    so ::ffff:127.0.0.1 and ::ffff:10.0.0.1 are blocked even on
    Python versions where is_global alone would pass them.
    """
    if not ip.is_global:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_global
    return True


def _resolve_validated(host):
    """Resolve once; return [(family, ip)] in resolver order.

    Raises ValidationError when the host does not resolve, and
    SSRFBlockedError when ANY resolved address is not public — the
    whole request is blocked, never just the bad address.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValidationError(f"cannot resolve host: {host}")
    if not infos:
        raise ValidationError(f"cannot resolve host: {host}")
    validated = []
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            raise SSRFBlockedError("blocked: address is not a valid IP")
        if not _is_public(ip):
            raise SSRFBlockedError(
                "blocked: URL resolves to a non-public address")
        validated.append((info[0], sockaddr[0]))
    return validated


def _check_host(host):
    _resolve_validated(host)


def _check_url_shape(parsed):
    """Scheme/hostname/credential checks shared by validate_url and
    the pinned fetch (every hop runs them before resolving)."""
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("url must start with http:// or https://")
    if not parsed.hostname:
        raise ValidationError("url must contain a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError("URLs with credentials are not allowed")


def validate_url(url):
    """Validate a URL for SSRF safety. Raises ValidationError or
    SSRFBlockedError; returns None when the URL may be fetched."""
    parsed = urllib.parse.urlparse(url)
    _check_url_shape(parsed)
    _check_host(parsed.hostname)


class SSRFRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that re-validates every redirect target.

    Kept for the existing test coverage; check_url_status no longer
    uses urllib — it follows redirects manually in fetch_head_pinned.
    """

    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_port(scheme):
    return 443 if scheme == "https" else 80


def _host_header(parsed):
    """Host header value: hostname, plus :port when non-default.

    An IPv6-literal hostname is bracketed, as a Host header requires.
    """
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    if port is not None and port != _default_port(parsed.scheme):
        return f"{host}:{port}"
    return host


def _pinned_head_once(url):
    """One HEAD hop to a pinned IP. Returns (status, location).

    The hostname is resolved once and every address validated; the
    socket connects to one of those validated addresses, in resolver
    order, and is never re-resolved. HTTPS wraps the pinned socket
    with the original hostname as SNI, so certificate verification
    still checks the hostname, not the IP.
    """
    parsed = urllib.parse.urlparse(url)
    _check_url_shape(parsed)
    hostname = parsed.hostname
    port = parsed.port or _default_port(parsed.scheme)
    host_header = _host_header(parsed)
    addresses = _resolve_validated(hostname)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    last_error = None
    sock = None
    for _family, ip in addresses:
        try:
            sock = socket.create_connection((ip, port),
                                            timeout=TIMEOUT_SECONDS)
            break
        except OSError as exc:
            last_error = exc
    if sock is None:
        raise last_error
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=hostname)
        conn = http.client.HTTPSConnection(hostname, port,
                                           timeout=TIMEOUT_SECONDS)
    else:
        conn = http.client.HTTPConnection(hostname, port,
                                          timeout=TIMEOUT_SECONDS)
    conn.sock = sock
    try:
        conn.request("HEAD", path, headers={
            "Host": host_header, "User-Agent": USER_AGENT})
        resp = conn.getresponse()
        status = resp.status
        location = resp.getheader("Location")
        resp.read()
    finally:
        conn.close()
    return status, location


# Redirect handling, mirroring urllib's HTTPRedirectHandler limits:
# at most 5 redirects, and a repeated target at most 4 times.
REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 5
MAX_REPEATS = 4


def fetch_head_pinned(url):
    """HEAD a URL over a pinned connection, following redirects manually.

    Returns (status, final_url). Each hop is resolved once, validated
    and pinned the same way; relative Location values are joined with
    the current URL and an HTTPS -> HTTP downgrade is followed, as
    urllib did. Raises SSRFBlockedError when any hop resolves to a
    non-public address, ValidationError for a bad URL, OSError for a
    network failure, and urllib.error.HTTPError when the redirect
    limit is hit — the same shape urllib raises, so check_url_status
    turns it into reachable True with the redirect status.
    """
    current = url
    visited = {}
    while True:
        status, location = _pinned_head_once(current)
        if status not in REDIRECT_STATUS_CODES:
            return status, current
        if location is None:
            # urllib raises HTTPError for a redirect with no Location.
            raise urllib.error.HTTPError(
                current, status, f"HTTP Error {status}: redirect with "
                "no Location header", None, None)
        target = urllib.parse.urljoin(current, location)
        scheme = urllib.parse.urlparse(target).scheme
        if scheme not in ("http", "https", "ftp"):
            # urllib rejects non-http(s)/ftp redirect schemes this way.
            raise urllib.error.HTTPError(
                current, status,
                f"Redirection to url '{target}' is not allowed", None, None)
        if (visited.get(target, 0) >= MAX_REPEATS
                or len(visited) >= MAX_REDIRECTS):
            raise urllib.error.HTTPError(
                current, status,
                "The HTTP server returned a redirect error that would "
                "lead to an infinite loop.", None, None)
        visited[target] = visited.get(target, 0) + 1
        current = target
