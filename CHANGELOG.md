# Changelog

All notable changes to Asmit Dev Tools are recorded here.

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
