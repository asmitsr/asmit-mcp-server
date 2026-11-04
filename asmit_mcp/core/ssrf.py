"""SSRF protection for user-supplied URLs (used by check_url_status).

Only check_url_status takes a URL from the caller; every other tool
talks to fixed API hosts, so this is the only SSRF surface in the
server. The guard runs BEFORE any request is made, and again for
every redirect target (urllib does not re-validate redirects itself).

Rules:
  - Scheme must be http or https; URLs carrying credentials are rejected.
  - The hostname must resolve, and EVERY resolved address must be
    globally routable (ip.is_global). That single rule blocks loopback,
    private, link-local (including cloud metadata 169.254.169.254),
    multicast, reserved and unspecified addresses, without maintaining
    a hand-written blocklist.
  - Resolved addresses are never echoed in error messages: an attacker
    probing internal hosts must not learn what resolved to what.
  - Redirects are validated by _SSRFRedirectHandler before following,
    at most 5 redirects.

This guard does not make a URL "safe" in general — it only stops the
server from being used to reach non-public addresses. The target server
itself is still untrusted.

Environment note: on networks where local DNS is intercepted (for
example a VM whose resolver maps every public hostname to a synthetic
reserved address such as 198.18.x.x for an egress proxy), this guard
is conservative — it blocks the URL instead of fetching it, because
the locally resolved address is not globally routable. It never fails
open: a private address is never allowed, even if that means a public
URL is blocked in such an environment. On a normal machine with direct
DNS, public URLs resolve to real global addresses and pass.
"""

import ipaddress
import socket
import urllib.parse
import urllib.request

from asmit_mcp.core.errors import ValidationError


class SSRFBlockedError(Exception):
    """Raised when a URL is blocked by the SSRF guard."""


def _check_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValidationError(f"cannot resolve host: {host}")
    if not infos:
        raise ValidationError(f"cannot resolve host: {host}")
    for info in infos:
        sockaddr = info[4]
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            raise SSRFBlockedError("blocked: address is not a valid IP")
        if not ip.is_global:
            raise SSRFBlockedError(
                "blocked: URL resolves to a non-public address")


def validate_url(url):
    """Validate a URL for SSRF safety. Raises ValidationError or
    SSRFBlockedError; returns None when the URL may be fetched."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("url must start with http:// or https://")
    if not parsed.hostname:
        raise ValidationError("url must contain a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError("URLs with credentials are not allowed")
    _check_host(parsed.hostname)


class SSRFRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that re-validates every redirect target."""

    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)
