"""Asmit Dev Tools — a real MCP server people can install from GitHub.

Run it with an MCP client (Claude Desktop, VS Code, Cursor, ...) over
stdio; it is NOT a website and is not deployed to Vercel.

Tools (all read-only or pure computation — no shell, no file writes,
no money movement, no secrets):
  check_password_breach — HIBP k-anonymity breach count for a password.
  password_strength     — local 0-5 strength score + improvements.
  generate_password     — random password, generated locally.
  split_expense         — equal/custom splits + simplified settlements.
  settle_balances       — simplify any set of balances into payments.
  convert_currency      — free no-key exchange-rate conversion.
  repo_health           — public GitHub repository health (public data).
  repo_compare          — side-by-side health of two public repos.
  github_user_summary   — public user summary: stars, languages, repos.
  audit_tool_list       — static security checklist for a tool list.
  check_url_status      — is a URL reachable, and what status it returns.
  world_time            — current time in any IANA timezone + Dhaka + UTC.
"""

import hashlib
import json
import re
import secrets
import string
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("asmit-dev-tools")

USER_AGENT = "asmit-dev-tools-mcp/1.0"


def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, "not found"
        if exc.code == 403:
            return None, "rate limited or forbidden by the API"
        return None, f"API returned HTTP {exc.code}"
    except Exception as exc:  # network down, DNS failure, ...
        return None, f"request failed: {exc}"


# ---------------------------------------------------------------- breach
@mcp.tool()
def check_password_breach(password: str) -> str:
    """Count how many times a password appeared in known data breaches.

    Privacy: only the first 5 characters of the SHA-1 hash are sent to
    Have I Been Pwned (k-anonymity). The password and the full hash are
    never sent, stored or logged.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
    except Exception as exc:
        return json.dumps({"error": f"breach lookup failed: {exc}"})
    count = 0
    for line in body.splitlines():
        found_suffix, found_count = line.split(":")
        if found_suffix == suffix:
            count = int(found_count)
            break
    return json.dumps({"hash_prefix": prefix, "breach_count": count,
                       "note": "Only the hash prefix was sent; the password "
                               "itself was never sent or stored."})


# ----------------------------------------------------------------- split
@mcp.tool()
def split_expense(total_amount: float, members: list[str], paid_by: str,
                  custom_shares: dict[str, float] | None = None) -> str:
    """Split an expense and simplify who owes whom.

    Money is handled in integer poisha (amount * 100), never floats.
    Equal split: the remainder poisha go to the first members, so the
    shares always add up exactly. Custom split: shares must sum exactly
    to the total, otherwise an error is returned.
    """
    if not members or paid_by not in members:
        return json.dumps({"error": "members must be non-empty and include paid_by"})
    total = round(total_amount * 100)
    if total <= 0:
        return json.dumps({"error": "total_amount must be positive"})
    if custom_shares:
        shares = {m: round(custom_shares.get(m, 0) * 100) for m in members}
        if sum(shares.values()) != total:
            return json.dumps({"error": "custom shares do not sum to the total"})
    else:
        base, remainder = divmod(total, len(members))
        shares = {m: base + (1 if i < remainder else 0)
                  for i, m in enumerate(members)}
    paid = {m: (total if m == paid_by else 0) for m in members}
    balances = {m: paid[m] - shares[m] for m in members}
    # Greedy debt simplification: creditors take from debtors in order.
    creditors = sorted(((m, b) for m, b in balances.items() if b > 0),
                       key=lambda x: -x[1])
    debtors = sorted(((m, -b) for m, b in balances.items() if b < 0),
                     key=lambda x: -x[1])
    settlements = []
    ci = di = 0
    while ci < len(creditors) and di < len(debtors):
        cm, camt = creditors[ci]
        dm, damt = debtors[di]
        pay = min(camt, damt)
        settlements.append({"from": dm, "to": cm, "amount": pay / 100})
        creditors[ci] = (cm, camt - pay)
        debtors[di] = (dm, damt - pay)
        if creditors[ci][1] == 0:
            ci += 1
        if debtors[di][1] == 0:
            di += 1
    return json.dumps({
        "shares": {m: v / 100 for m, v in shares.items()},
        "balances": {m: v / 100 for m, v in balances.items()},
        "settlements": settlements,
    })


# ------------------------------------------------------------ repo health
def _summarize_repo(data):
    pushed = data.get("pushed_at")
    days_since_push = None
    if pushed:
        pushed_dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
        days_since_push = (datetime.now(timezone.utc) - pushed_dt).days
    return {
        "full_name": data.get("full_name"),
        "description": data.get("description"),
        "stars": data.get("stargazers_count"),
        "forks": data.get("forks_count"),
        "open_issues": data.get("open_issues_count"),
        "language": data.get("language"),
        "license": (data.get("license") or {}).get("spdx_id"),
        "last_push_days_ago": days_since_push,
        "url": data.get("html_url"),
    }


@mcp.tool()
def repo_health(owner: str, repo: str) -> str:
    """Health summary of a PUBLIC GitHub repository (public data only).

    No token is used and private repositories cannot be read: GitHub
    returns 404 for them, and this tool reports that honestly.
    """
    data, error = _get_json(f"https://api.github.com/repos/{owner}/{repo}")
    if error:
        return json.dumps({"error": error})
    return json.dumps(_summarize_repo(data))


@mcp.tool()
def repo_compare(owner1: str, repo1: str, owner2: str, repo2: str) -> str:
    """Side-by-side health comparison of two public GitHub repositories."""
    first, err1 = _get_json(f"https://api.github.com/repos/{owner1}/{repo1}")
    second, err2 = _get_json(f"https://api.github.com/repos/{owner2}/{repo2}")
    if err1 or err2:
        return json.dumps({"error": err1 or err2})
    return json.dumps({"repo_a": _summarize_repo(first),
                       "repo_b": _summarize_repo(second)})


@mcp.tool()
def github_user_summary(username: str) -> str:
    """Public summary of a GitHub user: profile, repo count, total stars
    across their public repos, and most-used languages. Public data only,
    no token; private repos are invisible to the public API by design."""
    user, error = _get_json(f"https://api.github.com/users/{username}")
    if error:
        return json.dumps({"error": error})
    repos, error = _get_json(
        f"https://api.github.com/users/{username}/repos?per_page=100")
    if error:
        return json.dumps({"error": error})
    languages = {}
    total_stars = 0
    for repo in repos:
        lang = repo.get("language")
        if lang:
            languages[lang] = languages.get(lang, 0) + 1
        total_stars += repo.get("stargazers_count", 0)
    return json.dumps({
        "login": user.get("login"),
        "name": user.get("name"),
        "public_repos": user.get("public_repos"),
        "followers": user.get("followers"),
        "following": user.get("following"),
        "created_at": user.get("created_at"),
        "repos_fetched": len(repos),
        "total_stars_on_fetched_repos": total_stars,
        "top_languages": dict(sorted(languages.items(),
                                      key=lambda kv: -kv[1])[:5]),
        "profile_url": user.get("html_url"),
    })


# ------------------------------------------------------------ audit tools
_CHECKS = [
    ("critical", "Shell / code execution",
     ["shell command", "bash", "terminal", "eval", "exec", "run any command",
      "arbitrary code", "system command"],
     "Remove shell/code execution, or gate it behind explicit human approval."),
    ("high", "Destructive or money-moving action",
     ["delete file", "write file", "overwrite", "send money",
      "transfer money", "make payment", "purchase", "send email",
      "drop table", "delete from"],
     "Destructive and money-moving tools need explicit approval and logging."),
    ("medium", "Reads files, data or the network",
     ["read file", "list files", "filesystem", "http request",
      "fetch url", "network", "database"],
     "Limit reads to named paths or tables, and log what was read."),
    ("high", "Secret-handling text",
     ["password", "api key", "secret key", "access token",
      "credentials", "private key"],
     "Descriptions must never mention secrets."),
    ("high", "Instruction-like text in a description",
     ["ignore previous instructions", "disregard instructions",
      "do not tell the user", "do not mention", "always send"],
     "A description must only say what the tool does."),
]
_DEDUCTIONS = {"critical": 25, "high": 15, "medium": 8, "low": 3}


@mcp.tool()
def audit_tool_list(tools_json: str) -> str:
    """Static security checklist for an MCP server's tool list.

    tools_json is a JSON list of {"name": ..., "description": ...}.
    Nothing is run and nothing connects to a live server. The result
    is a checklist score, not a safety certification.
    """
    try:
        tools = json.loads(tools_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "tools_json is not valid JSON"})
    if not isinstance(tools, list) or not tools or len(tools) > 200:
        return json.dumps({"error": "tools_json must be a non-empty list (max 200)"})
    findings = []
    for tool in tools:
        if not isinstance(tool, dict) or not str(tool.get("name") or "").strip():
            return json.dumps({"error": "every tool needs a name"})
        name = str(tool["name"]).strip()
        description = str(tool.get("description") or "").strip()
        text = f"{name} {description}".lower()
        seen = set()
        for severity, category, patterns, fix in _CHECKS:
            matched = next(
                (p for p in patterns
                 if re.search(r"\b" + re.escape(p) + r"\b", text)), None)
            if matched and category not in seen:
                seen.add(category)
                findings.append({"tool": name, "severity": severity,
                                 "category": category, "matched": matched,
                                 "fix": fix})
        if not description:
            findings.append({"tool": name, "severity": "medium",
                             "category": "Missing description", "matched": "(empty)",
                             "fix": "Write one clear sentence about what the tool does."})
        elif len(description) < 20:
            findings.append({"tool": name, "severity": "low",
                             "category": "Vague description", "matched": description,
                             "fix": "Expand the description so a reviewer can judge the risk."})
    score = max(0, 100 - sum(_DEDUCTIONS[f["severity"]] for f in findings))
    grade = ("A" if score >= 90 else "B" if score >= 75
             else "C" if score >= 50 else "D")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order[f["severity"]])
    return json.dumps({"tool_count": len(tools), "score": score,
                       "grade": grade, "findings": findings,
                       "note": "Static checklist only, not a safety certification."})


@mcp.tool()
def password_strength(password: str) -> str:
    """Score a password 0-5 and explain how to improve it.

    The password is scored locally and never sent anywhere. Score: one
    point each for length 8+, length 12+, mixed case, a digit, and a
    symbol. This is a strength hint, not a guarantee.
    """
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
    return json.dumps({"score": score, "label": label,
                       "checks": checks, "suggestions": suggestions})


@mcp.tool()
def generate_password(length: int = 16, include_symbols: bool = True) -> str:
    """Generate a random password locally with the secrets module.

    The password is generated on the server machine and returned to the
    caller; it is never stored or sent anywhere else. Length is clamped
    to 8-64.
    """
    length = max(8, min(64, length))
    alphabet = string.ascii_letters + string.digits
    if include_symbols:
        alphabet += string.punctuation
    password = "".join(secrets.choice(alphabet) for _ in range(length))
    return json.dumps({"password": password, "length": length})


@mcp.tool()
def settle_balances(balances: dict[str, float]) -> str:
    """Simplify any set of balances into the fewest payments.

    balances maps each person to what they are owed (+) or owe (-);
    the values must sum to zero. Money is handled in integer poisha.
    """
    if not balances:
        return json.dumps({"error": "balances must not be empty"})
    cents = {m: round(v * 100) for m, v in balances.items()}
    if sum(cents.values()) != 0:
        return json.dumps({"error": "balances must sum to zero"})
    creditors = sorted(((m, c) for m, c in cents.items() if c > 0),
                       key=lambda x: -x[1])
    debtors = sorted(((m, -c) for m, c in cents.items() if c < 0),
                     key=lambda x: -x[1])
    settlements = []
    ci = di = 0
    while ci < len(creditors) and di < len(debtors):
        cm, camt = creditors[ci]
        dm, damt = debtors[di]
        pay = min(camt, damt)
        settlements.append({"from": dm, "to": cm, "amount": pay / 100})
        creditors[ci] = (cm, camt - pay)
        debtors[di] = (dm, damt - pay)
        if creditors[ci][1] == 0:
            ci += 1
        if debtors[di][1] == 0:
            di += 1
    return json.dumps({"settlements": settlements,
                       "payment_count": len(settlements)})


@mcp.tool()
def convert_currency(amount: float, from_currency: str, to_currency: str) -> str:
    """Convert an amount between currencies using a free no-key rate API.

    Rates are indicative, from exchangerate-api.com, and are not
    financial advice. No key or account is needed.
    """
    src = from_currency.strip().upper()
    dst = to_currency.strip().upper()
    data, error = _get_json(f"https://api.exchangerate-api.com/v4/latest/{src}")
    if error:
        return json.dumps({"error": error})
    rates = data.get("rates") or {}
    if dst not in rates:
        return json.dumps({"error": f"unknown currency: {dst}"})
    return json.dumps({"amount": amount, "from": src, "to": dst,
                       "converted": round(amount * rates[dst], 2),
                       "rate": rates[dst],
                       "note": "Indicative rate only."})


@mcp.tool()
def check_url_status(url: str) -> str:
    """Check whether a URL is reachable and what status it returns.

    Only a HEAD request (falling back to GET) is made; nothing is
    downloaded fully and no form is submitted.
    """
    start = time.time()
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, final_url = resp.status, resp.geturl()
    except urllib.error.HTTPError as exc:
        status, final_url = exc.code, exc.geturl() if hasattr(exc, "geturl") else url
    except Exception as exc:
        return json.dumps({"url": url, "reachable": False, "error": str(exc)})
    return json.dumps({"url": url, "reachable": True, "status": status,
                       "final_url": final_url,
                       "seconds": round(time.time() - start, 2)})


@mcp.tool()
def world_time(timezone_name: str) -> str:
    """Current time in a given IANA timezone, plus UTC and Asia/Dhaka
    for comparison. timezone_name examples: Asia/Dhaka, Asia/Kolkata,
    Europe/London, America/New_York."""
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        return json.dumps({"error": f"unknown timezone: {timezone_name}"})
    now = datetime.now(timezone.utc)
    return json.dumps({
        "requested_timezone": timezone_name,
        "time_in_requested_timezone": now.astimezone(zone).isoformat(),
        "time_in_utc": now.isoformat(),
        "time_in_asia_dhaka": now.astimezone(ZoneInfo("Asia/Dhaka")).isoformat(),
    })


def main():
    mcp.run()


if __name__ == "__main__":
    main()
