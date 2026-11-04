"""Standard response format (v1.1.0, backwards compatible).

Success: {"ok": true, ...data} — data keys are unchanged from v1.0.0,
so existing readers keep working; only "ok" is added.
Error:   {"ok": false, "error": "human-readable message",
          "error_code": "VALIDATION_ERROR" | "NOT_FOUND" |
                        "RATE_LIMITED" | "EXTERNAL_API_ERROR" |
                        "SSRF_BLOCKED" | "UNKNOWN_ERROR"}

"error" stays a plain string on purpose: v1.0.0 readers that read
error as a string keep working. "error_code" is the new machine-readable
field; "ok" is the new quick check.

Convention: input problems raise ValidationError (or SSRFBlockedError)
and server.py converts them; external API problems return failure()
directly, so their code (NOT_FOUND, RATE_LIMITED, ...) is preserved
instead of collapsing to UNKNOWN_ERROR.
"""

import json

VALIDATION_ERROR = "VALIDATION_ERROR"
NOT_FOUND = "NOT_FOUND"
RATE_LIMITED = "RATE_LIMITED"
EXTERNAL_API_ERROR = "EXTERNAL_API_ERROR"
SSRF_BLOCKED = "SSRF_BLOCKED"
UNKNOWN_ERROR = "UNKNOWN_ERROR"


class ValidationError(Exception):
    """Raised for bad input. server.py converts it to VALIDATION_ERROR."""


def success(data):
    result = {"ok": True}
    result.update(data)
    return json.dumps(result)


def failure(code, message):
    return json.dumps({"ok": False, "error": message, "error_code": code})
