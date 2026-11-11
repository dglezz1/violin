"""Regex trigger table for the two-level scanner.

The regex layer is the cheap, deterministic first filter: it recognises a
vulnerability class or a technology signal from the literal text of a target
response. The embedding layer only runs when this table finds nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Trigger classes. ``kind`` is either ``vuln`` (a vulnerability class that the
# guard can route) or ``tech`` (a technology signal such as a cloud provider).
TRIGGERS: dict[str, dict[str, Any]] = {
    "sqli": {
        "kind": "vuln",
        "patterns": [
            r"SQLSTATE\[[0-9A-Z]{5}",
            r"mysql_fetch_(array|row|assoc)",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"You have an error in your SQL syntax",
            r"sqlite3?\.OperationalError",
            r"JDBCException",
            r"com\.mysql\.jdbc\.exceptions",
            r"pg_query\(\)",
            r"UNION ALL SELECT",
            r"sleep\(\d+\)",
            r"information_schema\.tables",
        ],
        "skills": ["web-app", "security/web-pentest-workflow"],
        "labels": ["SQL error", "database error"],
    },
    "ssrf": {
        "kind": "vuln",
        "patterns": [
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
            r"AzureWe\.net",
            r"interact\.sh",
            r"oastify\.com",
            r"requestbin\.(?:com|net)",
            r"canarytokens\.com",
            r"Connection refused.*127\.0\.0\.1",
            r"curl:\s*\(\d+\)",
        ],
        "skills": ["api-testing", "web-app"],
        "labels": ["cloud metadata", "OOB callback", "internal address"],
    },
    "xss": {
        "kind": "vuln",
        "patterns": [
            r"Content-Security-Policy",
            r"alert\(document\.cookie\)",
            r"onerror\s*=",
            r"<script>alert\(",
            r"innerHTML",
            r"dangerouslySetInnerHTML",
        ],
        "skills": ["web-app"],
        "labels": ["script injection", "DOM sink"],
    },
    "ssti": {
        "kind": "vuln",
        "patterns": [
            r"TemplateSyntaxError",
            r"jinja2\.exceptions",
            r"UndefinedError.*template",
            r"FreeMarker.*Error",
            r"VelocityException",
            r"Could not parse.*expression",
            r"Unexpected token.*JSON at position",
        ],
        "skills": ["web-app", "security/web-pentest-workflow"],
        "labels": ["template engine error"],
    },
    "idor": {
        "kind": "vuln",
        "patterns": [
            r"\b(?:403|404)\b.*\b(?:Forbidden|Not Found)\b",
            r"user_not_found",
            r"not authorized to access",
            r"resource does not exist or you do not have access",
            r"permission denied for (?:table|sequence|schema)",
        ],
        "skills": ["identity-auth", "api-testing"],
        "labels": ["access control response"],
    },
    "auth-bypass": {
        "kind": "vuln",
        "patterns": [
            r"X-Forwarded-For.*admin",
            r"bypass.*auth",
            r"jwt\.MalformedError",
            r"JWT signature verification failed",
            r"InvalidAlgorithm",
            r"alg\":\s*\"none\"",
            r"kid\":\s*\"|jwk.*injection",
        ],
        "skills": ["identity-auth"],
        "labels": ["token verification"],
    },
    "path-traversal": {
        "kind": "vuln",
        "patterns": [
            r"\.\./\.\./etc/passwd",
            r"Directory traversal",
            r"Path Traversal",
            r"Invalid file path",
        ],
        "skills": ["web-app"],
        "labels": ["file path escape"],
    },
    "deserialization": {
        "kind": "vuln",
        "patterns": [
            r"java\.io\.ObjectInputStream",
            r"ObjectInputStream",
            r"yaml\.constructor",
            r"unserialize\(",
            r"__reduce__",
            r"pickle\.loads",
        ],
        "skills": ["web-app"],
        "labels": ["unsafe deserialization"],
    },
    "command-injection": {
        "kind": "vuln",
        "patterns": [
            r"uid=\d+\(.*\) gid=\d+",
            r"/bin/sh: .*command not found",
            r"command not found",
            r"bash: .*: command not found",
            r"subprocess\.CalledProcessError",
        ],
        "skills": ["web-app"],
        "labels": ["shell output"],
    },
    "aws": {
        "kind": "tech",
        "patterns": [
            r"\.amazonaws\.com",
            r"AKIA[0-9A-Z]{16}",
            r"ASIA[0-9A-Z]{16}",
            r"aws-sdk",
            r"AmazonS3",
            r"AccessDenied",
            r"aws4_request",
            r"SignatureDoesNotMatch",
        ],
        "skills": ["security/aws-cloud-misconfiguration"],
        "labels": ["AWS"],
    },
    "gcp": {
        "kind": "tech",
        "patterns": [
            r"storage\.googleapis\.com",
            r"\.iam\.gserviceaccount\.com",
            r"googleapis\.com",
            r"403 Forbidden.*storage",
        ],
        "skills": ["security/gcp-cloud-misconfiguration"],
        "labels": ["GCP"],
    },
    "azure": {
        "kind": "tech",
        "patterns": [
            r"\.blob\.core\.windows\.net",
            r"\.azurewebsites\.net",
            r"AccountKey",
            r"SharedAccessSignature",
        ],
        "skills": ["security/azure-cloud-misconfiguration"],
        "labels": ["Azure"],
    },
    "graphql": {
        "kind": "tech",
        "patterns": [
            r"GraphQL request error",
            r"GRAPHQL_VALIDATION_FAILED",
            r"Cannot query field",
            r"__schema",
            r"introspection",
        ],
        "skills": ["api-testing", "web-app"],
        "labels": ["GraphQL"],
    },
    "kubernetes": {
        "kind": "tech",
        "patterns": [
            r"k8s\.io/",
            r"kube-system",
            r"kubectl",
            r"serviceaccount",
        ],
        "skills": ["security/k8s-misconfiguration"],
        "labels": ["Kubernetes"],
    },
    "jwt": {
        "kind": "tech",
        "patterns": [
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.",
            r"\"alg\"\s*:\s*\"(HS256|RS256|none)\"",
            r"\"typ\"\s*:\s*\"JWT\"",
        ],
        "skills": ["identity-auth"],
        "labels": ["JWT"],
    },
}


@dataclass
class Trigger:
    """One compiled trigger class."""

    name: str
    kind: str
    patterns: tuple[re.Pattern[str], ...]
    skills: tuple[str, ...]
    labels: tuple[str, ...]
    raw: dict[str, Any] = field(default_factory=dict)


def _compile(name: str, spec: dict[str, Any]) -> Trigger:
    patterns = tuple(re.compile(p, re.IGNORECASE) for p in spec.get("patterns", []))
    return Trigger(
        name=name,
        kind=spec.get("kind", "vuln"),
        patterns=patterns,
        skills=tuple(spec.get("skills", ())),
        labels=tuple(spec.get("labels", ())),
        raw=spec,
    )


def load_triggers(path: Path | None = None) -> dict[str, Trigger]:
    """Load the trigger table, preferring a deployment override on disk."""
    source = path or _default_trigger_path()
    if source and source.is_file():
        try:
            data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            data = {}
        if isinstance(data, dict) and data:
            return {
                name: _compile(name, spec)
                for name, spec in data.items()
                if isinstance(spec, dict) and spec.get("patterns")
            }
    return {name: _compile(name, spec) for name, spec in TRIGGERS.items()}


def _default_trigger_path() -> Path | None:
    import os

    override = os.environ.get("VIOLIN_TRIGGERS_PATH", "").strip()
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parent.parent / "assets" / "triggers.yaml"


def scan_text(text: str, triggers: dict[str, Trigger]) -> list[tuple[Trigger, str]]:
    """Return every (trigger, matched snippet) found in ``text``."""
    if not text:
        return []
    hits: list[tuple[Trigger, str]] = []
    for trigger in triggers.values():
        for pattern in trigger.patterns:
            match = pattern.search(text)
            if match:
                start = max(0, match.start() - 60)
                end = min(len(text), match.end() + 60)
                hits.append((trigger, text[start:end].strip()))
                break
    return hits
