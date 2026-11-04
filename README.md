# Asmit Dev Tools — MCP Server

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-12_tools-7c3aed?style=flat-square)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

A small, safe MCP server that other people can install from GitHub and
connect to Claude Desktop, VS Code, Cursor or any MCP client. It is a
program, not a website — it runs over stdio and is not deployed to Vercel.

## Tools

| Tool | What it does |
| --- | --- |
| `check_password_breach` | Counts how many times a password appeared in known breaches. Only the first 5 characters of the SHA-1 hash are sent to Have I Been Pwned (k-anonymity); the password and full hash are never sent or stored. |
| `password_strength` | Local 0-5 strength score for a password, with improvement suggestions. Nothing is sent anywhere. |
| `generate_password` | Random password generated locally with the `secrets` module. Never stored or sent elsewhere. |
| `split_expense` | Splits an expense equally or by custom shares and simplifies who owes whom. Money is handled in integer poisha, never floats, so shares always add up exactly. |
| `settle_balances` | Simplifies any set of balances (who is owed / owes) into the fewest payments. |
| `convert_currency` | Converts between currencies with a free no-key exchange-rate API. Indicative rates only. |
| `repo_health` | Health summary of a **public** GitHub repository: stars, forks, open issues, language, license, days since last push. No token is used; private repos return "not found" by GitHub's design. |
| `repo_compare` | Side-by-side health of two public repositories. |
| `github_user_summary` | Public user summary: repo count, followers, total stars on fetched repos, top languages. Public data only. |
| `audit_tool_list` | Static security checklist for an MCP server's tool list (score + findings + fixes). Nothing is run and nothing connects to a live server. |
| `check_url_status` | Checks whether a URL is reachable and what status it returns (HEAD, falling back on error). |
| `world_time` | Current time in any IANA timezone, plus UTC and Asia/Dhaka. |

Deliberately **not** included: shell execution, file writes, database
writes, money movement, or anything that handles secrets. Those are
exactly the capabilities the MCP security discussion warns about.

## Install and use

Requires Python 3.10+.

```bash
git clone https://github.com/asmitsr/asmit-mcp-server.git
cd asmit-mcp-server
python -m venv .venv
.venv/bin/pip install .
```

Claude Desktop config (`claude_desktop_config.json`), using `uvx`:

```json
{
  "mcpServers": {
    "asmit-dev-tools": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/asmitsr/asmit-mcp-server.git", "asmit-dev-tools"]
    }
  }
}
```

Or run the server directly for testing:

```bash
.venv/bin/python server.py
```

## Example prompts (once connected)

- "Check whether the password `password` has appeared in a breach."
- "Split 900 taka between A, B and C, paid by A, and tell me who owes whom."
- "How healthy is the public repo asmitsr/DoremanAI?"
- "Audit this tool list for security risks: ..."

## Test

Protocol test (stdio, lists tools and calls each one):

```bash
.venv/bin/python test_client.py
```

Offline unit tests for the pure-computation tools:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

The test client connects over stdio, lists the tools, and calls each
one: a known breached password, a random password, a 900/3 split, a
public repo, and safe vs risky tool lists for the audit.

## Honest limits

- This server never runs shell commands, never writes files, and never
  moves money. That is a safety choice, not a missing feature.
- `repo_health` uses GitHub's unauthenticated public API, so it is
  subject to GitHub's 60 requests/hour limit for shared IPs.
- MCP clients pass only a small environment whitelist to a stdio
  server by default. If your network needs a proxy, add its variables
  in your client's `env` config for this server; the included
  `test_client.py` forwards the machine's proxy variables for the
  same reason (values are read at runtime, never stored in the repo).
- `audit_tool_list` is a static checklist, not a safety certification.
  A high score does not prove a server is safe.
- Never give this server (or any MCP server) your API keys, passwords
  or tokens. It does not need them.
