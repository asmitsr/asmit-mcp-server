"""Explicit input validation for every tool.

FastMCP/Pydantic already rejects wrong JSON types at the protocol
level. These helpers add the domain rules on top: non-empty strings,
length caps (so a huge input cannot be used to slow the server),
GitHub name shapes (so a name cannot smuggle a "/" into an API URL),
finite numbers, and bounded collections. Violations raise
ValidationError; server.py turns that into a clean VALIDATION_ERROR
response, never a traceback.
"""

import math
import re

from .errors import ValidationError

_GITHUB_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def req_str(value, field, max_len=1000):
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    value = value.strip()
    if len(value) > max_len:
        raise ValidationError(f"{field} must be at most {max_len} characters")
    return value


def req_github_name(value, field):
    value = req_str(value, field, max_len=100)
    if (not _GITHUB_NAME.match(value) or value.startswith((".", "-"))
            or ".." in value):
        raise ValidationError(f"{field} is not a valid GitHub name")
    return value


def req_amount(value, field="amount"):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be a number")
    if not math.isfinite(value) or value <= 0 or value > 1e12:
        raise ValidationError(f"{field} must be between 0 and 1e12")
    return float(value)


def req_members(value):
    if not isinstance(value, list) or not value or len(value) > 100:
        raise ValidationError("members must be a list of 1-100 names")
    return [req_str(m, "member name", max_len=100) for m in value]


def req_balances(value):
    if not isinstance(value, dict) or not value or len(value) > 200:
        raise ValidationError("balances must be a non-empty object (max 200 entries)")
    cleaned = {}
    for name, amount in value.items():
        if not isinstance(name, str) or not name.strip():
            raise ValidationError("balance names must be non-empty strings")
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) \
                or not math.isfinite(amount):
            raise ValidationError(f"balance for {name!r} must be a finite number")
        cleaned[name.strip()] = float(amount)
    return cleaned


def req_url(value):
    value = req_str(value, "url", max_len=2048)
    if not value.startswith(("http://", "https://")):
        raise ValidationError("url must start with http:// or https://")
    return value


def req_text(value, field, max_len=50000):
    return req_str(value, field, max_len=max_len)
