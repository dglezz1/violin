#!/usr/bin/env python3
"""Burp Suite pipeline: the twin of zap-pipeline.py, for the Pro REST API.

Violin's tool-catalog already lists burpsuite; this script makes it
orchestratable the same way ZAP is — but only when the operator enabled
Burp's REST API (User options → Suite → REST API, default
http://127.0.0.1:1337/v0.1/). It is strictly opt-in: Burp Pro is licensed,
its API is off by default, and the script fails closed when the API is not
there. The GUI stays the operator's; the script only reads and maps.

Exports Burp's issue list, maps each issue type to the guard's canonical
vulnerability class, and writes the same lead journal the ZAP pipeline
produces (evidence/burp/alerts.jsonl) — the agent verifies leads through the
guard; a Burp issue is a lead with a vendor confidence, not a finding.

Usage (from the engagement root, via violin_exec):

    python3 scripts/burp-pipeline.py --target http://localhost:3000 \\
        --burp http://127.0.0.1:1337/v0.1 --out evidence/burp
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Burp issue type -> the guard's canonical vulnerability class. Burp numbers
# its issue types (the API returns "issue_typeid"); the map covers the common
# web set by name so unknown issues keep class "review".
ISSUE_CLASS: dict[str, str] = {
    "SQL injection": "sqli",
    "Cross-site scripting (reflected)": "xss",
    "Cross-site scripting (stored)": "xss",
    "Cross-site scripting (DOM-based)": "xss",
    "Cross-site request forgery": "csrf",
    "Directory traversal": "path-traversal",
    "File path manipulation": "path-traversal",
    "Server-side template injection": "ssti",
    "Server-side request forgery": "ssrf",
    "External service interaction (DNS/HTTP)": "ssrf",
    "Broken authentication": "missing-authentication",
    "Authentication bypass": "auth-bypass",
    "Privilege escalation": "broken-access-control",
    "Access control violation": "broken-access-control",
    "Insecure deserialization": "deserialization",
    "XML external entity injection": "xxe",
    "LDAP injection": "ldap-injection",
    "Open redirection": "open-redirect",
    "Open redirection (DOM-based)": "open-redirect",
    "Mass assignment": "mass-assignment",
    "Business logic vulnerability": "business-logic",
    "Rate limiting": "rate-limit",
    "CORS misconfiguration": "cors",
    "Misconfigured security headers": "misconfiguration",
    "Cross-origin resource sharing: unencrypted origin": "cors",
    "Cookie without Secure flag": "misconfiguration",
    "Cookie without HttpOnly flag": "misconfiguration",
    "Session token in URL": "missing-authentication",
    "Private IP addresses disclosed": "sensitive-data-exposure",
    "Email addresses disclosed": "sensitive-data-exposure",
    "Information disclosure in error messages": "input-validation",
    "Use of a broken or risky cryptographic algorithm": "cryptographic-issues",
    "Weak MD5-hashed credentials": "cryptographic-issues",
}

_RISK_ORDER = {"High": "high", "Medium": "medium", "Low": "low", "Information": "info"}


def _burp_call(burp: str, path: str, timeout: float = 30.0):
    request = urllib.request.Request(f"{burp.rstrip('/')}{path}")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def map_issues(issues: list[dict], target: str) -> dict:
    out = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "total": len(issues),
        "by_class": {},
        "alerts": [],
    }
    for issue in issues:
        name = str(issue.get("issue_type") or issue.get("name") or "")
        cls = ISSUE_CLASS.get(name, "review")
        risk = _RISK_ORDER.get(str(issue.get("severity") or ""), "info")
        entry = {
            "alert": name,
            "class": cls,
            "risk": risk,
            "confidence": issue.get("confidence"),
            "url": issue.get("url") or (issue.get("location") or ""),
            "param": issue.get("parameter"),
            "attack": (issue.get("request_response") or "")[:200] if isinstance(issue.get("request_response"), str) else "",
            "evidence": (issue.get("issue_detail") or issue.get("detail") or "")[:300],
        }
        out["alerts"].append(entry)
        out["by_class"][cls] = out["by_class"].get(cls, 0) + 1
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True)
    parser.add_argument("--burp", default="http://127.0.0.1:1337/v0.1")
    parser.add_argument("--out", default="evidence/burp")
    parser.add_argument("--wait", type=float, default=10.0)
    args = parser.parse_args()

    deadline = time.monotonic() + args.wait
    issues: list[dict] = []
    while time.monotonic() < deadline:
        try:
            data = _burp_call(args.burp, "/burp/scanner/scans")
            issues = data.get("issues") or []
            break
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            time.sleep(2.0)
    if not issues:
        print(
            "burp-pipeline: no issues from the REST API — enable it in Burp "
            "(User options → Suite → REST API) or run a scan first; for the "
            "keyless path use zap-pipeline.py",
            file=sys.stderr,
        )
        return 2

    mapped = map_issues(issues, args.target)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "alerts.json").write_text(json.dumps(mapped, indent=1))
    with (out / "alerts.jsonl").open("w") as fh:
        for entry in mapped["alerts"]:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    summary = ", ".join(f"{c}:{n}" for c, n in sorted(mapped["by_class"].items(), key=lambda kv: -kv[1]))
    print(
        f"burp-pipeline: {mapped['total']} issues -> {out/'alerts.jsonl'}; "
        f"by class: {summary or 'none'}; each issue is a LEAD — verify through "
        "the guard before submitting."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
