"""Developer utility tools: UUID, hashing, Base64/URL codec.

All pure local computation on text — no network, no files, no shell.
Inputs are size-capped by req_text; invalid choices raise
ValidationError, which server.py turns into a clean response.
"""

import base64
import binascii
import hashlib
import uuid
from urllib.parse import quote, unquote

from asmit_mcp.core.errors import ValidationError, success
from asmit_mcp.core.validation import req_str, req_text

_HASHES = ("sha256", "sha1", "md5")
_OPS = ("base64_encode", "base64_decode", "url_encode", "url_decode")


def generate_uuid(count: int = 1) -> str:
    """Generate 1-100 random UUID v4 values locally."""
    if isinstance(count, bool) or not isinstance(count, int) \
            or not 1 <= count <= 100:
        raise ValidationError("count must be an integer between 1 and 100")
    return success({"uuids": [str(uuid.uuid4()) for _ in range(count)],
                    "count": count, "version": 4})


def hash_text(text: str, algorithm: str = "sha256") -> str:
    """Hash text with SHA-256 (default), SHA-1 or MD5; returns hex.

    SHA-1/MD5 are for checksums and compatibility only, never for
    passwords or security. The text is hashed locally, never sent
    anywhere.
    """
    text = req_text(text, "text")
    algorithm = req_str(algorithm, "algorithm", max_len=20).lower()
    if algorithm not in _HASHES:
        raise ValidationError(
            f"algorithm must be one of: {', '.join(_HASHES)}")
    digest = hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
    return success({"algorithm": algorithm, "hash": digest,
                    "input_length": len(text)})


def codec_base64_url(text: str, operation: str = "base64_encode") -> str:
    """Base64 or URL encode/decode of text.

    operation: base64_encode, base64_decode, url_encode, url_decode.
    Invalid Base64 input is a validation error, never a crash.
    """
    text = req_text(text, "text")
    operation = req_str(operation, "operation", max_len=20).lower()
    if operation not in _OPS:
        raise ValidationError(
            f"operation must be one of: {', '.join(_OPS)}")
    if operation == "base64_encode":
        result = base64.b64encode(text.encode("utf-8")).decode("ascii")
    elif operation == "base64_decode":
        try:
            result = base64.b64decode(text, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            raise ValidationError("text is not valid Base64") from None
    elif operation == "url_encode":
        result = quote(text, safe="")
    else:
        result = unquote(text)
    return success({"operation": operation, "result": result})
