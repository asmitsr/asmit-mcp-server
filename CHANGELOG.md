# Changelog

All notable changes to Asmit Dev Tools are recorded here.

## Unreleased — Phase 1: Security & Architecture (branch `phase-1-security`, not merged)

### Security

- SSRF guard for `check_url_status` (`core/ssrf.py`): only http/https,
  no credentials in URLs, hostname must resolve to globally routable
  addresses only (blocks localhost, private, link-local including cloud
  metadata 169.254.169.254, multicast, reserved), every redirect target
  re-validated, max 5 redirects. Resolved addresses are never echoed in
  error messages.
- Explicit input validation (`core/validation.py`): types, ranges,
  length caps, GitHub name shapes, finite numbers, 3-letter currency
  codes. Bad input returns a clean error, never a traceback.
- Logging to stderr only, recording tool name, success/failure,
  duration and error code — never inputs, passwords, tokens or arguments.
- Outgoing calls: 15-second timeouts, 2 MB response cap, per-host rate
  limit (50 calls/minute), currency rates cached in memory for 5 minutes.

### Changed

- Modular structure: `server.py` is now only the registrar; tools live
  in `tools/` (security, finance, github, utility) and shared helpers
  in `core/` (errors, validation, http, cache, ratelimit, ssrf).
- Standard error format: success `{"ok": true, ...data}`; errors
  `{"ok": false, "error": "message", "error_code": "CODE"}`. The
  `error` field stays a plain string, so v1.0.0 readers keep working.
- `repo_health` now also returns top languages by bytes and open pull
  requests counted from the first 100; failures of those extra calls
  report null instead of failing the whole health check.
- `check_url_status` timeout standardised to 15 seconds.
- Tests: 28 unit tests (was 13), including SSRF, redirect-handler,
  rate-limit, timeout, currency-failure and expense edge cases;
  protocol test updated with an SSRF assertion and the upgraded
  `repo_health` fields. Ruff clean.

### Known limitations of this phase

- The public-URL path of `check_url_status` could not be verified
  end-to-end in the proxied test environment (local DNS maps every
  hostname to a synthetic reserved address, so the guard blocks it
  there). Guard logic itself is verified with mocked DNS and private
  addresses. See README "Honest limits".
- Client compatibility (Claude Desktop, VS Code, Cursor) is still
  untested — it needs a PC. Nothing is claimed about it.
- CI is not in this branch: the GitHub App cannot create workflow
  files, so `.github/workflows/ci.yml` is prepared separately for
  addition via the web UI after this phase.

## v1.0.0 — 4 November 2026

### Added

- MCP server over stdio (Python + FastMCP), installable from GitHub.
- 12 tools, all read-only or pure computation:
  - `check_password_breach` — HIBP k-anonymity breach count (prefix only).
  - `password_strength` — local 0-5 strength score with suggestions.
  - `generate_password` — random password generated locally.
  - `split_expense` — equal/custom splits in integer poisha.
  - `settle_balances` — debt simplification into the fewest payments.
  - `convert_currency` — free no-key exchange-rate conversion.
  - `repo_health` — public GitHub repository health.
  - `repo_compare` — side-by-side health of two public repos.
  - `github_user_summary` — public user summary (stars, languages).
  - `audit_tool_list` — static security checklist for a tool list.
  - `check_url_status` — URL reachability and status.
  - `world_time` — current time in any IANA timezone, plus Dhaka and UTC.
- `test_client.py` — protocol test over stdio: lists tools and calls each one.
- `tests/test_units.py` — unit tests for the pure-computation tools.
- `SECURITY.md`, MIT `LICENSE`, and a Claude Desktop config example.

### Fixed during development

- Pinned `mcp>=1.0,<2`: pip installed mcp 2.x, which renamed FastMCP
  to MCPServer and broke the v1 import.
- The MCP stdio client inherits only a small environment whitelist and
  drops proxy variables, so the server subprocess failed all HTTPS calls
  with an SSL error while direct calls worked. `test_client.py` now
  forwards the machine's proxy variables from its own environment at
  runtime (never hardcoded).

### Verified

- Full protocol test passed 4 November 2026: 12 tools listed, known
  breached password 52,372,427, random password 0, 900/3 split settled
  as B→A 300 and C→A 300, risky audit 45/D with a Critical finding,
  safe audit 100/A.
