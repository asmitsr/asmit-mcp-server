"""Small HTTP helpers for the public, no-key APIs this server uses.

Timeouts are always set, so a dead API cannot hang a tool call.
Failures are mapped to (code, message) pairs from asmit_mcp.core.errors, never
raised as tracebacks to the client.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from asmit_mcp.core.errors import EXTERNAL_API_ERROR, NOT_FOUND, RATE_LIMITED
from asmit_mcp.core.ratelimit import RATE_LIMITER

USER_AGENT = "asmit-dev-tools-mcp/1.1"
TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 2_000_000


def _check_rate_limit(url):
    host = urllib.parse.urlparse(url).hostname or ""
    if not RATE_LIMITER.allow(host):
        return (RATE_LIMITED,
                "local rate limit exceeded for this host; try again shortly")
    return None


def _read_capped(resp):
    data = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ValueError("response too large")
    return data


def get_json(url):
    """Return (data, None) on success or (None, (code, message))."""
    limited = _check_rate_limit(url)
    if limited:
        return None, limited
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.loads(_read_capped(resp).decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, (NOT_FOUND, "not found")
        if exc.code == 403:
            return None, (RATE_LIMITED, "rate limited or forbidden by the API")
        return None, (EXTERNAL_API_ERROR, f"API returned HTTP {exc.code}")
    except (OSError, ValueError) as exc:
        # URLError/TimeoutError are OSError; JSON/UTF-8 errors are ValueError.
        return None, (EXTERNAL_API_ERROR, f"request failed: {exc}")


def get_text(url):
    """Like get_json, but for plain-text endpoints (HIBP range API)."""
    limited = _check_rate_limit(url)
    if limited:
        return None, limited
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return _read_capped(resp).decode("utf-8"), None
    except (OSError, ValueError) as exc:
        return None, (EXTERNAL_API_ERROR, f"request failed: {exc}")
