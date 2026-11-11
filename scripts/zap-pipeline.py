#!/usr/bin/env python3
"""ZAP pipeline: the proxy scans, this maps its alerts into the engagement.

The heavy work is mechanical and stays off-model: ZAP daemon does the
spider/passive/active scan; this script exports the alerts, maps each one to
the guard's canonical vulnerability class, and writes an alerts journal plus a
compact summary the agent can consume in one turn. Findings are still verified
by the agent through the guard — an alert is a lead with evidence, not a
finding.

Usage (from the engagement root, via violin_exec):

    python3 scripts/zap-pipeline.py --target http://localhost:3000 \\
        --zap http://127.0.0.1:8090 --out evidence/zap --mode passive

    # one-time setup, from a host terminal (never a target command):
    zap-cli start -port 8090        # or: zap.sh -daemon -port 8090 -config ...
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ZAP alert name -> the guard's canonical vulnerability class. Alerts the map
# does not cover keep class "review" — a lead the agent reads, not a verdict.
ALERT_CLASS: dict[str, str] = {
    "SQL Injection": "sqli",
    "SQL Injection - SQLite": "sqli",
    "Cross Site Scripting (Reflected)": "xss",
    "Cross Site Scripting (Persistent)": "xss",
    "Cross Domain Misconfiguration": "cors",
    "CORS Misconfiguration": "cors",
    "Path Traversal": "path-traversal",
    "Remote File Inclusion": "ssrf",
    "Server Side Request Forgery": "ssrf",
    "Bypassable 404": "broken-access-control",
    "Absence of Anti-CSRF Tokens": "csrf",
    "Anti-CSRF Tokens Check": "csrf",
    "Insecure HTTP Method": "misconfiguration",
    "X-Content-Type-Options Header Missing": "misconfiguration",
    "Content Security Policy (CSP) Header Not Set": "misconfiguration",
    "Strict-Transport-Security Header Not Set": "misconfiguration",
    "Web Browser XSS Protection Not Enabled": "misconfiguration",
    "Backup File": "path-traversal",
    "Directory Browsing": "misconfiguration",
    "Hidden File Found": "security-through-obscurity",
    "Interesting Response": "false-positive",
    "Information Disclosure - Debug Error Messages": "input-validation",
    "Information Disclosure - Sensitive Information in URL": "sensitive-data-exposure",
    "Information Disclosure - Sensitive Information in HTTP Referrer Header": "sensitive-data-exposure",
    "Private IP Disclosure": "sensitive-data-exposure",
    "Session ID in URL Rewrite": "missing-authentication",
    "User Agent Fuzzer": "input-validation",
    "Buffer Overflow": "input-validation",
    "LDAP Injection": "ldap-injection",
    "XPath Injection": "xpath-injection",
    "Expression Language Injection": "ssti",
    "Server Side Template Injection": "ssti",
    "External Redirect": "open-redirect",
    "Allow Self-closing on non-void HTML elements": "false-positive",
    "Serialization of User Input": "deserialization",
    "Base64 Disclosure": "security-through-obscurity",
}

_RISK_ORDER = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def _zap_call(zap: str, path: str, params: dict | None = None, timeout: float = 30.0):
    query = urllib.parse.urlencode(params or {})
    url = f"{zap.rstrip('/')}{path}?{query}" if params else f"{zap.rstrip('/')}{path}"
    request = urllib.request.Request(url)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def wait_for_zap(zap: str, deadline_s: float = 120.0) -> bool:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            _zap_call(zap, "/JSON/core/view/version/")
            return True
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(2.0)
    return False


def run_scan(zap: str, target: str, mode: str, max_children: int) -> None:
    _zap_call(zap, "/JSON/core/action/newAlert/", {"url": target}) if False else None
    _zap_call(zap, "/JSON/core/action/accessUrl/", {"url": target, "followRedirects": "true"})
    _zap_call(zap, "/JSON/spider/action/scan/", {"url": target, "maxChildren": str(max_children)})
    while True:
        status = _zap_call(zap, "/JSON/spider/view/status/")["status"]
        if str(status) == "100":
            break
        time.sleep(3.0)
    if mode in {"active", "full"}:
        _zap_call(zap, "/JSON/ascan/action/scan/", {"url": target, "recurse": "true"})
        while True:
            status = _zap_call(zap, "/JSON/ascan/view/status/")["status"]
            if str(status) == "100":
                break
            time.sleep(5.0)


def export_alerts(zap: str, target: str) -> list[dict]:
    base = "{scheme}://{host}".format(**urllib.parse.urlsplit(target)._asdict()) if "//" in target else target
    data = _zap_call(zap, "/JSON/core/view/alerts/", {"baseurl": target, "start": "0", "count": "9999"})
    return data.get("alerts") or []


def map_alerts(alerts: list[dict]) -> dict:
    out = {"generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
           "total": len(alerts), "by_class": {}, "alerts": []}
    for alert in alerts:
        name = str(alert.get("alert") or "")
        cls = ALERT_CLASS.get(name, "review")
        risk = _RISK_ORDER.get(str(alert.get("risk") or ""), "info")
        entry = {
            "alert": name,
            "class": cls,
            "risk": risk,
            "confidence": alert.get("confidence"),
            "url": alert.get("url"),
            "param": alert.get("param"),
            "attack": (alert.get("attack") or "")[:200],
            "evidence": (alert.get("evidence") or "")[:200],
            "description": (alert.get("description") or "")[:400],
        }
        out["alerts"].append(entry)
        out["by_class"][cls] = out["by_class"].get(cls, 0) + 1
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", required=True)
    parser.add_argument("--zap", default="http://127.0.0.1:8090")
    parser.add_argument("--out", default="evidence/zap")
    parser.add_argument("--mode", choices=["passive", "active", "full"], default="passive")
    parser.add_argument("--max-children", type=int, default=50)
    parser.add_argument("--wait-zap", type=float, default=120.0)
    args = parser.parse_args()

    if not wait_for_zap(args.zap, args.wait_zap):
        print("zap-pipeline: ZAP API is not reachable; start the daemon first", file=sys.stderr)
        return 2

    run_scan(args.zap, args.target, args.mode, args.max_children)
    alerts = export_alerts(args.zap, args.target)
    mapped = map_alerts(alerts)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "alerts.json").write_text(json.dumps(mapped, indent=1))
    with (out / "alerts.jsonl").open("w") as fh:
        for entry in mapped["alerts"]:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    summary = ", ".join(f"{cls}:{n}" for cls, n in sorted(mapped["by_class"].items(), key=lambda kv: -kv[1]))
    print(
        f"zap-pipeline: {mapped['total']} alerts -> {out/'alerts.jsonl'}; "
        f"open queue: alerts.jsonl; by class: {summary or 'none'}; "
        f"each alert is a LEAD: verify through the guard before submitting."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
