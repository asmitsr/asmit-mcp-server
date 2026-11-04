"""Asmit Dev Tools — a real MCP server people can install from GitHub.

Run it with an MCP client (Claude Desktop, VS Code, Cursor, ...) over
stdio; it is NOT a website and is not deployed to Vercel.

Architecture (Phase 1): this file is only the registrar. Tool logic
lives in tools/ (one module per category) and shared helpers live in
core/ (error format, validation, HTTP, cache). A tool change touches
one module, not the whole server.

Tools (all read-only or pure computation — no shell, no file writes,
no money movement, no secrets): see README.md and docs/TOOLS.md.

Logging: structured logs go to STDERR only, because stdout is the MCP
protocol channel. A log line records tool name, success/failure,
duration and error code — never inputs, passwords, tokens or arguments.
"""

import functools
import json
import logging
import sys
import time

from mcp.server.fastmcp import FastMCP

from core.errors import UNKNOWN_ERROR, ValidationError, failure
from core.ssrf import SSRFBlockedError
from tools import finance, github, security, utility

mcp = FastMCP("asmit-dev-tools")

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("asmit-dev-tools")

ALL_TOOLS = [
    security.check_password_breach,
    utility.password_strength,
    utility.generate_password,
    finance.split_expense,
    finance.settle_balances,
    finance.convert_currency,
    github.repo_health,
    github.repo_compare,
    github.github_user_summary,
    security.audit_tool_list,
    utility.check_url_status,
    utility.world_time,
]


def logged(func):
    """Wrap a tool with timing + stderr logging and central error handling.

    functools.wraps preserves the original signature, so FastMCP still
    builds the correct tool schema from it. ValidationError becomes a
    clean VALIDATION_ERROR response; any unexpected exception becomes
    UNKNOWN_ERROR — the client never sees a traceback.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        try:
            result = func(*args, **kwargs)
        except ValidationError as exc:
            result = failure("VALIDATION_ERROR", str(exc))
        except SSRFBlockedError:
            result = failure("SSRF_BLOCKED",
                             "blocked: URL resolves to a non-public address")
        except Exception:  # noqa: BLE001 - central handler must never crash
            result = failure(UNKNOWN_ERROR, "unexpected server error")
        try:
            parsed = json.loads(result)
        except ValueError:
            parsed = {}
        ok = parsed.get("ok", True) if isinstance(parsed, dict) else True
        code = parsed.get("error_code") if isinstance(parsed, dict) else None
        logger.info("tool=%s ok=%s duration_ms=%d%s",
                    func.__name__, ok, int((time.time() - start) * 1000),
                    f" error_code={code}" if code else "")
        return result
    return wrapper


for _tool in ALL_TOOLS:
    mcp.tool()(logged(_tool))


def main():
    mcp.run()


if __name__ == "__main__":
    main()
