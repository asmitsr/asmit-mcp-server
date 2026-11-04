"""Security tools: breach check and tool-list audit.

Neither tool runs anything, writes anything, or handles secrets.
The breach check sends only a hash prefix (k-anonymity); the audit
reads tool names/descriptions only.
"""

import hashlib
import json
import re

from asmit_mcp.core.errors import ValidationError, failure, success
from asmit_mcp.core.http import get_text
from asmit_mcp.core.validation import req_str, req_text

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


def check_password_breach(password: str) -> str:
    """Count how many times a password appeared in known data breaches.

    Privacy: only the first 5 characters of the SHA-1 hash are sent to
    Have I Been Pwned (k-anonymity). The password and the full hash are
    never sent, stored or logged.
    """
    password = req_str(password, "password", max_len=10000)
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    body, error = get_text(f"https://api.pwnedpasswords.com/range/{prefix}")
    if error:
        return failure(error[0], f"breach lookup failed: {error[1]}")
    count = 0
    for line in body.splitlines():
        found_suffix, found_count = line.split(":")
        if found_suffix == suffix:
            count = int(found_count)
            break
    return success({"hash_prefix": prefix, "breach_count": count,
                    "note": "Only the hash prefix was sent; the password "
                            "itself was never sent or stored."})


def audit_tool_list(tools_json: str) -> str:
    """Static security checklist for an MCP server's tool list.

    tools_json is a JSON list of {"name": ..., "description": ...}.
    Nothing is run and nothing connects to a live server. The result
    is a checklist score, not a safety certification.
    """
    tools_json = req_text(tools_json, "tools_json", max_len=50000)
    try:
        tools = json.loads(tools_json)
    except json.JSONDecodeError:
        raise ValidationError("tools_json is not valid JSON")
    if not isinstance(tools, list) or not tools or len(tools) > 200:
        raise ValidationError("tools_json must be a non-empty list (max 200)")
    findings = []
    for tool in tools:
        if not isinstance(tool, dict) or not str(tool.get("name") or "").strip():
            raise ValidationError("every tool needs a name")
        name = str(tool["name"]).strip()
        description = str(tool.get("description") or "").strip()
        text = f"{name} {description}".lower()
        seen = set()
        for severity, category, patterns, fix in _CHECKS:
            # Word-boundary match, so "evaluate" does not trip "eval"
            # and "execute" does not trip "exec".
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
    return success({"tool_count": len(tools), "score": score,
                    "grade": grade, "findings": findings,
                    "note": "Static checklist only, not a safety certification."})
