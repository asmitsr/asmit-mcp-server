# Security Policy

## Supported version

Only the latest release on the `main` branch is supported with security
fixes.

## What this server never does

- It never runs shell commands or arbitrary code.
- It never writes or deletes files.
- It never moves money or submits forms.
- It never asks for, stores, or sends API keys, passwords, tokens or
  other credentials. `check_password_breach` sends only the first 5
  characters of a SHA-1 hash to Have I Been Pwned; the password itself
  never leaves the machine except as that prefix, by design of the
  k-anonymity API.

If you find a version of this server doing any of the above, it is not
this project — do not connect to it.

## Reporting a vulnerability

Open a GitHub Issue titled "Security:" with a description of the issue
and steps to reproduce it. Do not include real passwords, tokens or
other secrets in the report — use example values only.

## Audit note

`audit_tool_list` is a static checklist, not a safety certification.
A high score does not prove a server is safe, and a low score means
"review this before connecting", not proof of an attack.
