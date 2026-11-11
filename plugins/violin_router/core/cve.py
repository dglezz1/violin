"""Recent-CVE lookup for the technologies a finding touches.

OSV.dev is queried first because it needs no key and covers npm, PyPI, Go,
Rust and the major ecosystems. A small set of curated vendor advisories is
consulted for platforms that do not publish to OSV.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

# Ecosystem hints per technology keyword detected in a finding.
ECOSYSTEM_HINTS: dict[str, tuple[str, ...]] = {
    "node": ("npm",),
    "npm": ("npm",),
    "express": ("npm",),
    "react": ("npm",),
    "next": ("npm",),
    "angular": ("npm",),
    "vue": ("npm",),
    "lodash": ("npm",),
    "axios": ("npm",),
    "jquery": ("npm",),
    "python": ("PyPI",),
    "django": ("PyPI",),
    "flask": ("PyPI",),
    "fastapi": ("PyPI",),
    "requests": ("PyPI",),
    "pyyaml": ("PyPI",),
    "jinja": ("PyPI",),
    "requests-": ("PyPI",),
    "java": ("Maven",),
    "spring": ("Maven",),
    "log4j": ("Maven",),
    "struts": ("Maven",),
    "net": ("NuGet",),
    "aspnet": ("NuGet",),
    "go": ("Go",),
    "golang": ("Go",),
    "gin": ("Go",),
    "echo": ("Go",),
    "ruby": ("RubyGems",),
    "rails": ("RubyGems",),
    "php": ("Packagist",),
    "laravel": ("Packagist",),
    "symfony": ("Packagist",),
    "rust": ("crates.io",),
    "docker": ("crates.io",),
}


@dataclass(frozen=True)
class CveEntry:
    """One advisory."""

    id: str
    summary: str
    aliases: tuple[str, ...]
    severity: str = ""
    fixed_version: str = ""
    url: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "aliases": list(self.aliases),
            "severity": self.severity,
            "fixed_version": self.fixed_version,
            "url": self.url,
        }


def _request_json(url: str, payload: dict[str, Any] | None = None, timeout: float = 20.0) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    key = os.environ.get("OSV_API_KEY", "").strip()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def _severity_of(vuln: dict[str, Any]) -> str:
    database = vuln.get("database_specific") or {}
    severity = database.get("severity")
    if isinstance(severity, str) and severity:
        return severity
    for entry in vuln.get("severity") or []:
        score = entry.get("score")
        if score:
            return str(score)
    return ""


def _fixed_version(vuln: dict[str, Any]) -> str:
    for affected in vuln.get("affected") or []:
        for range_entry in affected.get("ranges") or []:
            for event in range_entry.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def query_osv(package: str, ecosystem: str, version: str = "") -> list[CveEntry]:
    """Query OSV for one package, optionally pinned to a version."""
    payload: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    try:
        data = _request_json(OSV_QUERY_URL, payload)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    entries: list[CveEntry] = []
    for vuln in data.get("vulns") or []:
        aliases = tuple(str(a) for a in (vuln.get("aliases") or []))
        entries.append(
            CveEntry(
                id=str(vuln.get("id") or ""),
                summary=str(vuln.get("summary") or ""),
                aliases=aliases,
                severity=_severity_of(vuln),
                fixed_version=_fixed_version(vuln),
                url=f"https://osv.dev/vulnerability/{vuln.get('id')}",
            )
        )
    return entries


def search_osv(query: str, limit: int = 10) -> list[CveEntry]:
    """Keyword search across OSV advisories."""
    url = f"{OSV_VULN_URL}?{urllib.parse.urlencode({'query': query})}"
    try:
        data = _request_json(url)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    entries: list[CveEntry] = []
    for vuln in (data.get("vulns") or [])[:limit]:
        aliases = tuple(str(a) for a in (vuln.get("aliases") or []))
        entries.append(
            CveEntry(
                id=str(vuln.get("id") or ""),
                summary=str(vuln.get("summary") or ""),
                aliases=aliases,
                severity=_severity_of(vuln),
                fixed_version=_fixed_version(vuln),
                url=f"https://osv.dev/vulnerability/{vuln.get('id')}",
            )
        )
    return entries


def ecosystems_for(technology: str) -> tuple[str, ...]:
    """Map a technology keyword to the ecosystems worth querying."""
    key = (technology or "").strip().lower()
    if not key:
        return ()
    if key in ECOSYSTEM_HINTS:
        return ECOSYSTEM_HINTS[key]
    for hint, ecosystems in ECOSYSTEM_HINTS.items():
        if hint in key:
            return ecosystems
    return ()


def lookup(technology: str, version: str = "", package: str = "") -> dict[str, Any]:
    """Look up recent advisories for a technology, package or keyword."""
    name = (package or technology or "").strip()
    if not name:
        return {"technology": technology, "package": "", "advisories": [], "note": "nothing to look up"}
    ecosystems = ecosystems_for(name) or ecosystems_for(technology)
    results: list[CveEntry] = []
    if ecosystems:
        for ecosystem in ecosystems:
            results.extend(query_osv(name, ecosystem, version))
    if not results:
        results = search_osv(name)
    deduped: dict[str, CveEntry] = {}
    for entry in results:
        deduped.setdefault(entry.id, entry)
    advisories = list(deduped.values())[:15]
    return {
        "technology": technology,
        "package": name,
        "version": version,
        "ecosystems": list(ecosystems),
        "advisories": [entry.as_dict() for entry in advisories],
        "count": len(advisories),
    }
