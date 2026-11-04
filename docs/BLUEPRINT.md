> Note (Phase 2, namespace move): the code described below now lives under `asmit_mcp/` — `asmit_mcp/server.py`, `asmit_mcp/core/`, `asmit_mcp/tools/`. Path references in the audit and Phase 1 decisions below refer to the pre-Phase-2 layout and are kept as written.

# Final Upgrade Blueprint — Asmit Dev Tools MCP Server

Goal: turn a working 12-tool MCP server into a professional, secure,
extensible **international open-source developer toolkit** — without
rewriting it, faking evidence, or adding dangerous capabilities.

## 0. Decisions (locked by this blueprint)

| Question | Decision | Why |
| --- | --- | --- |
| Final goal | International open-source MCP toolkit | A commercial platform needs payments, support and a team; a 100+ tool ecosystem is not a solo first-year project during a study routine. Open source is achievable and honest. |
| Interface | Local MCP server only | The server is a stdio program, not a website and not a desktop app. A dashboard is optional later (see Phase 4), never the core product. Hosting stays at 0 servers. |
| Tool count | Improve the 12, then expand to 30–50 via a plugin/module system | Freezing at 12 wastes the architecture; promising 100+ now is not credible. 30–50 is reachable in steps, each step tested. |
| Stack | Python + FastMCP v1, stdlib-first | The tested code is Python. Switching to TypeScript/Node would discard all verified work for no user benefit. See "Corrections" below. |

## 1. Audit — verified state on 4 November 2026

Audited files (10 pushed to `asmitsr/asmit-mcp-server`, public, main,
commit `98e36c8`, plus the provider's initial commit):

- `server.py` — 439 lines, single file, 12 tools (see README).
- `test_client.py` — stdio protocol test, ALL PASS.
- `tests/test_units.py` — 13 unit tests, OK (offline, pure tools only).
- `pyproject.toml` — `mcp>=1.0,<2` (v1 pinned; mcp 2.x renamed FastMCP).
- `README.md`, `LICENSE` (MIT), `CHANGELOG.md`, `SECURITY.md`.
- `examples/claude_desktop_config.json`.

Missing (do NOT claim these exist yet):

- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `docs/` (this file is the first),
  `Dockerfile`, `.github/` (no workflows, no issue/PR templates, no Dependabot).
- Structured logging: none in `server.py` today (only FastMCP's own stderr logs).
- Currency caching: none yet (every conversion calls the rate API).
- Rate limiting: none yet (single local user over stdio; see Phase 1).
- Central error format: inconsistent today — most tools return
  `{"error": "..."}`, but shapes differ. Phase 1 standardises this
  **together with the tests**, so no client breaks silently.
- Client compatibility: tested only with the Python MCP client over
  stdio. Claude Desktop, VS Code, Cursor, Windsurf and Continue have
  NOT been tested (they need a PC; the author works phone-only).
  Config examples exist for Claude only; VS Code/Cursor examples are
  Phase 4 work, not verified claims.
- Tool output today is JSON **strings**. FastMCP structured output
  (returning dicts) is a Phase 1 compatibility review item, not a
  claim about the current server.

## 2. Corrections to earlier suggestions (important)

These were in suggestions sent to the project and are **wrong for this
project** as written. The blueprint follows the corrected versions:

- **Zod does not apply.** Zod is a TypeScript library. This server is
  Python. The Python equivalent is **Pydantic**, and FastMCP already
  uses it: tool function signatures are validated at call time, and
  invalid arguments return an error to the client instead of crashing
  the server. Phase 1 adds explicit, uniform validation on top of that
  — it does not add Zod and does not rewrite the server in TypeScript.
- **Node CI does not apply.** A workflow using `setup-node` / `npm ci` /
  `npm test` cannot test a Python project. The correct CI is Python:
  `setup-python`, `pip install`, `ruff check`, unit tests, protocol test.
- **TypeScript file paths do not apply.** There is no `src/tools/*.ts`
  or `index.ts` here. New tools go in a Python `tools/` package (Phase 1)
  and are registered in the server module; tests go in `tests/`.
- **A GitHub Token is not required.** The server uses only public,
  no-key APIs by design. There is nothing to validate in `.env`, so no
  `.env.example` with keys will be invented. The only environment
  concern is proxy variables on networks that need them (documented
  in the README; the test client forwards them at runtime).
- **A file-parsing tool must not take a file path.** A tool that reads
  an arbitrary local path would let a client read any file on the
  machine — a security hole in a public installable server. The safe
  version accepts CSV/JSON **text** as input and summarises that text.
  No filesystem access is added.
- **No fake evidence, ever.** No "build passing" badge before a real CI
  run passes. No demo GIF/screenshot of Claude running a tool unless it
  is a real capture. No "100% coverage" claim: 100% is a goal, not a
  guarantee, and coverage is reported as measured, never as a target
  presented as achieved.
- **QR codes and IP lookups are deferred, not core.** QR generation
  needs an image dependency and image output support in clients; IP
  lookup sends an address to a third-party service. Both are optional
  later tools with privacy notes, not Phase 2 promises.

## 3. Phases

### Phase 1 — Security & architecture (highest priority)

- Standard error format for every tool, with tests updated together.
- Pydantic-style validation review: every tool validates its inputs
  explicitly (types, ranges, size caps: tool lists, text inputs,
  patterns, URLs) and returns a clean error, never a traceback.
- Structured logging to **stderr only** (stdout is the MCP channel):
  tool name, success/failure, duration, API status. **Never log inputs,
  passwords, tokens or tool arguments.**
- Currency-rate cache (short TTL, in memory) so repeated conversions
  do not hammer the rate API. GitHub data is not cached long (it changes).
- Modular structure, done as a refactor with tests green at each step:
  `tools/github.py`, `tools/finance.py`, `tools/utility.py`,
  `tools/security.py`, plus a small core (`validation`, `errors`,
  `logging`, `cache`). No behaviour change in this refactor except the
  error format and logging above.
- Upgrade `repo_health` instead of duplicating it: add language
  breakdown and open-PR count where the public API provides them.
  (A separate "GitHub Repository Health Checker" tool would duplicate
  an existing tool and is not added.)

Success: unit tests + protocol test pass, `ruff check` clean,
no tool reads files, runs shell, moves money, or handles secrets.

### Phase 2 — Improve the 12, add safe developer utilities

Improve, don't replace: breach check stays k-anonymous (prefix only);
strength becomes an advanced analyzer (still local); split/settle stay
integer-poisha; currency gains the cache from Phase 1; URL check gains
a header analysis that **redacts Set-Cookie values**; world time gains
a planner form (a time in one zone shown in several zones).

New tools (all stdlib-first, all validated, all tested):

- `format_json` — parse/format/validate JSON text (with a repair mode
  only for clearly safe fixes: trailing commas, single quotes — and an
  explicit note when repair changed the input; never silently rewrite).
- `test_regex` — pattern + text, both size-capped, with match list.
  No timeout guarantee is claimed (Python `re` has none); caps are the
  mitigation and are documented.
- `generate_uuid`, `hash_text` — UUID v4 and SHA-256/SHA-1/MD5 of text.
- `codec_base64_url` — Base64 and URL encode/decode of text.
- `decode_jwt_unverified` — decode header/payload **without verifying
  the signature**, labelled unverified in every response. It never
  accepts or uses a secret. Do not use its output for authentication.
- `dns_lookup` — hostname to addresses via the system resolver.
- `diff_text` — unified diff of two texts.
- `convert_units` — length/weight/temperature conversion (pure math).
- `summarize_data_text` — summary of CSV/JSON **text** (rows, columns,
  types). No file paths, no filesystem access.

That takes the server from 12 to about 21 tools. Each new tool ships
with a unit test and a docs entry in the same change, or it does not ship.

Explicitly **not** in Phase 2: system CPU/RAM monitoring (needs a new
dependency and exposes machine internals; reconsider only as an opt-in
later tool), QR generation, IP lookup, file-path parsing (see §2).

### Phase 3 — Plugin system & contribution path

- A documented tool-registration pattern: one module per category,
  one function per tool, one test file per module. A contributor adds
  a tool by adding a module + tests + docs, without touching other tools.
- `CONTRIBUTING.md` (exact Python paths, test commands, the
  no-shell/no-file/no-money/no-secret rules) and `CODE_OF_CONDUCT.md`.
- `docs/TOOLS.md` — every tool's inputs, outputs and an example.
  This file, not a screenshot, is the interactive documentation.
- Troubleshooting/FAQ in the README (proxy env, GitHub rate limits,
  mcp v1 pin, client config mistakes).

This phase is what makes 30–50 tools credible later. It does not by
itself add 30 tools.

### Phase 4 — Configuration & compatibility (medium priority)

- Config generator examples for Claude Desktop, VS Code, Cursor,
  Windsurf and Continue, each in `examples/`, each labelled as an
  example to copy — **not** as tested on that client, unless a real
  test on that client has happened.
- A compatibility note per client: what is known (stdio, Python client
  tested) vs unknown (client-specific quirks untested phone-only).
- Optional, separate, later: an opt-in local stats file (tool name,
  success/failure, duration only — never inputs) and a small local
  viewer for it. This is **not** a web dashboard product and it is not
  part of the MCP server's core. It is only built if the author wants it
  after Phase 3, because a stdio server has no usage data unless it
  deliberately writes a local log.

### Phase 5 — CI/CD, coverage, releases (via the owner route)

Hard constraint, stated plainly: the GitHub App used here **cannot
create or update `.github/workflows/*` files (403)**. The same applies
to repository topics and description (no update-repository tool) and
to releases (no create-release tool in the connector). These are owner
actions, not connector actions. The honest route is:

- Prepare `ci.yml` (Python CI: setup-python, pip install, ruff,
  unit tests, protocol test), issue templates, a pull-request template
  and Dependabot config locally.
- Add the workflow/topics/description/release through the owner's
  signed-in browser session (a browser task) or by the owner in the
  GitHub web UI. Only then may a CI badge be added to the README, and
  only after a real run passes.
- Coverage is measured with `coverage.py` and reported as measured.
  Target 80%+ for the pure tools is a goal; network tools are covered
  by the protocol test, not by unit tests, and that distinction is
  stated in the coverage report.
- Releases use semantic versioning (`v1.0.0` notes already exist in
  `CHANGELOG.md`). A release is created by the owner; the changelog
  entry is the release note source.
- PyPI publishing is a separate, later decision: it needs a PyPI
  account, a package-name availability check, and a token handled
  through secure storage — never in chat, never in the repo. `npm`
  does not apply to this Python server.
- MCP registry/directory submission is last, after a release exists:
  it needs an account, a review, and meeting that registry's criteria.
  Submission is not a guarantee of listing.

### Phase 6 — Community launch (last step)

Only after Phases 1–5: topics/description set, release published,
docs complete, CI green. Then announce (showcase/dev.to), invite
issues, and review contributions against the CONTRIBUTING rules.
Stars and contributors are outcomes, not promises in this blueprint.

## 4. What this project will never do

Shell execution, arbitrary file reads/writes, database writes, money
movement, secret handling, fake screenshots/badges/coverage claims,
or presenting another project's work as its own. Any suggestion that
requires one of these is rejected, with the reason stated.
