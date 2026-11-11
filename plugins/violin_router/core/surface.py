"""Resolve a detected class or target surface to the playbook that covers it.

The guard routes a vulnerability class to the skill Violin ships. That answer
is correct but narrow: a class such as ``sqli`` maps to one bundled playbook
while the wider pool holds several that cover the same class from different
angles.

This module resolves the *surface* instead: the target-facing command, the
detected class and the technology seen in the output decide which pool
playbooks apply. The result is attached to a dispatch note, so the agent is
told what to read before it tests, without anyone having to name the skill.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# The table ships with the plugin; a deployment may override it.
_DEFAULT_TABLE = Path(__file__).resolve().parent.parent / "assets" / "surface_playbooks.yaml"


@dataclass(frozen=True)
class PlaybookRef:
    """One playbook the agent should read before testing."""

    name: str
    note: str = ""


@dataclass(frozen=True)
class SurfaceEntry:
    """One row of the surface table."""

    key: str
    classes: tuple[str, ...]
    surfaces: tuple[str, ...]
    skills: tuple[PlaybookRef, ...]


_TABLE_CACHE: dict[str, tuple[SurfaceEntry, ...]] = {}


def _table_path() -> Path:
    override = os.environ.get("VIOLIN_SURFACE_TABLE", "").strip()
    return Path(override).expanduser() if override else _DEFAULT_TABLE


def load_table(path: Path | None = None) -> tuple[SurfaceEntry, ...]:
    """Load the surface table (cached per path)."""
    target = path or _table_path()
    key = str(target)
    cached = _TABLE_CACHE.get(key)
    if cached is not None:
        return cached
    entries: list[SurfaceEntry] = []
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        data = {}
    if isinstance(data, dict):
        for name, spec in data.items():
            if not isinstance(spec, dict):
                continue
            skills = []
            for item in spec.get("skills") or []:
                if isinstance(item, dict) and item.get("name"):
                    skills.append(PlaybookRef(str(item["name"]), str(item.get("note") or "")))
                elif isinstance(item, str):
                    skills.append(PlaybookRef(item, ""))
            entries.append(
                SurfaceEntry(
                    key=str(name),
                    classes=tuple(str(c) for c in (spec.get("classes") or [])),
                    surfaces=tuple(str(c) for c in (spec.get("surfaces") or [])),
                    skills=tuple(skills),
                )
            )
    result = tuple(entries)
    _TABLE_CACHE[key] = result
    return result


def resolve(
    vulnerability_class: str = "",
    command: str = "",
    signal: str = "",
    table: tuple[SurfaceEntry, ...] | None = None,
) -> list[PlaybookRef]:
    """The playbooks that apply to a class and a target surface.

    A class match alone is enough; a surface match adds the playbooks that
    cover that part of the application. The result is ordered so the most
    specific match comes first and duplicates are removed.
    """
    entries = table if table is not None else load_table()
    if not entries:
        return []
    haystack = f"{command} {signal}".lower()
    wanted = (vulnerability_class or "").strip().lower()

    scored: list[tuple[int, PlaybookRef]] = []
    for entry in entries:
        class_hit = bool(wanted) and wanted in entry.classes
        surface_hit = any(marker.lower() in haystack for marker in entry.surfaces)
        if not class_hit and not surface_hit:
            continue
        # A class match is a stronger signal than a surface match.
        weight = 2 if class_hit else 1
        for ref in entry.skills:
            scored.append((weight, ref))

    scored.sort(key=lambda item: -item[0])
    seen: set[str] = set()
    ordered: list[PlaybookRef] = []
    for _, ref in scored:
        if ref.name in seen:
            continue
        seen.add(ref.name)
        ordered.append(ref)
    return ordered


def describe(refs: list[PlaybookRef]) -> str:
    """Render the playbooks for a dispatch note."""
    if not refs:
        return ""
    return " · ".join(f"{ref.name}" + (f" ({ref.note})" if ref.note else "") for ref in refs)


def guard_vocabulary() -> tuple[str, ...]:
    """The vulnerability classes the guard can route, read from the guard itself.

    The agent can only test a class the guard knows how to route, so the
    exhaustive standard ("every class, against every route") is only
    reachable if the agent knows the full list. The guard's routing table is
    the authority; the router surfaces it.
    """
    try:
        from .binding import _load_guard_policy
    except Exception:
        return ()
    policy = _load_guard_policy()
    if policy is None:
        return ()
    routes = getattr(policy, "_VULNERABILITY_ROUTES", None)
    if not isinstance(routes, dict):
        return ()
    return tuple(sorted(str(key) for key in routes))


def as_dicts(refs: list[PlaybookRef]) -> list[dict[str, Any]]:
    return [{"name": ref.name, "note": ref.note} for ref in refs]
