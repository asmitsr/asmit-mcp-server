"""Utility tools: password helpers, URL status, world time.

All local computation except check_url_status, which makes one HEAD
request (nothing is downloaded fully, no form is submitted).
"""

import secrets
import string
import time
import urllib.error
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from asmit_mcp.core.errors import SSRF_BLOCKED, failure, success
from asmit_mcp.core.ssrf import SSRFBlockedError, fetch_head_pinned, validate_url
from asmit_mcp.core.validation import ValidationError, req_str, req_url


def password_strength(password: str) -> str:
    """Score a password 0-5 and explain how to improve it.

    The password is scored locally and never sent anywhere. Score: one
    point each for length 8+, length 12+, mixed case, a digit, and a
    symbol. This is a strength hint, not a guarantee.
    """
    password = req_str(password, "password", max_len=10000)
    checks = {
        "length_8_plus": len(password) >= 8,
        "length_12_plus": len(password) >= 12,
        "mixed_case": (any(c.islower() for c in password)
                       and any(c.isupper() for c in password)),
        "has_digit": any(c.isdigit() for c in password),
        "has_symbol": any(c in string.punctuation for c in password),
    }
    score = sum(checks.values())
    suggestions = []
    if not checks["length_12_plus"]:
        suggestions.append("Use at least 12 characters.")
    if not checks["mixed_case"]:
        suggestions.append("Mix upper- and lower-case letters.")
    if not checks["has_digit"]:
        suggestions.append("Add a digit.")
    if not checks["has_symbol"]:
        suggestions.append("Add a symbol such as ! or #.")
    label = ("Very weak" if score <= 1 else "Weak" if score == 2
             else "Fair" if score == 3 else "Strong" if score == 4
             else "Very strong")
    return success({"score": score, "label": label,
                    "checks": checks, "suggestions": suggestions})


def generate_password(length: int = 16, include_symbols: bool = True) -> str:
    """Generate a random password locally with the secrets module.

    The password is generated on the server machine and returned to the
    caller; it is never stored or sent anywhere else. Length is clamped
    to 8-64.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValidationError("length must be an integer")
    length = max(8, min(64, length))
    alphabet = string.ascii_letters + string.digits
    if include_symbols:
        alphabet += string.punctuation
    password = "".join(secrets.choice(alphabet) for _ in range(length))
    return success({"password": password, "length": length})


def check_url_status(url: str) -> str:
    """Check whether a URL is reachable and what status it returns.

    SSRF guard (core.ssrf) runs before the request and again for every
    redirect target: only globally routable addresses may be fetched,
    at most 5 redirects. The connection goes to a validated IP (DNS
    pinning) via fetch_head_pinned; redirects are followed manually.
    Only a HEAD request is made; nothing is downloaded fully and no
    form is submitted. "reachable: false" is a result, not an error:
    it means the check itself ran and the URL did not answer.
    """
    url = req_url(url)
    try:
        validate_url(url)
    except SSRFBlockedError:
        return failure(SSRF_BLOCKED,
                       "blocked: URL resolves to a non-public address")
    start = time.time()
    try:
        status, final_url = fetch_head_pinned(url)
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = exc.geturl() if hasattr(exc, "geturl") else url
    except SSRFBlockedError:
        return failure(SSRF_BLOCKED,
                       "blocked: redirect target is not a public address")
    except (OSError, ValueError) as exc:
        # URLError/TimeoutError are OSError; anything else unexpected
        # is already converted by the server wrapper for MCP callers.
        return success({"url": url, "reachable": False, "error": str(exc)})
    return success({"url": url, "reachable": True, "status": status,
                    "final_url": final_url,
                    "seconds": round(time.time() - start, 2)})


def world_time(timezone_name: str) -> str:
    """Current time in a given IANA timezone, plus UTC and Asia/Dhaka
    for comparison. timezone_name examples: Asia/Dhaka, Asia/Kolkata,
    Europe/London, America/New_York."""
    timezone_name = req_str(timezone_name, "timezone_name", max_len=100)
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        raise ValidationError(f"unknown timezone: {timezone_name}")
    now = datetime.now(timezone.utc)
    return success({
        "requested_timezone": timezone_name,
        "time_in_requested_timezone": now.astimezone(zone).isoformat(),
        "time_in_utc": now.isoformat(),
        "time_in_asia_dhaka": now.astimezone(ZoneInfo("Asia/Dhaka")).isoformat(),
    })
