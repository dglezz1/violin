"""Index build: turn the skill pool into a searchable vector index.

The build is a side effect of the pool, not of an engagement: it runs when the
set of skills changes, not per session. The pool digest stored alongside the
index is what decides whether a rebuild is needed at all.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .catalog import SkillEntry, SkillSource, collect_entries, pool_digest
from .embedding import EmbeddingError, build_embedder
from .index import SkillIndex, default_index_dir

# Local pools the router draws from. Missing roots are skipped silently so the
# plugin still works on a machine that only has Violin installed.
HERMES_SKILLS = Path.home() / ".hermes" / "skills"
STRIX_SKILLS = Path.home() / ".strix" / "skills"
STRIX_REPO_SKILLS = Path.home() / "Developer" / "Pentesting" / "strix-v.2" / "skills"


def default_sources(violin_skills: Path | None = None) -> list[SkillSource]:
    """The unified pool: Violin, Hermes security skills, Strix and Dark-Moon.

    The whole Hermes catalog is indexed as reference so that a query can
    reach any playbook, while only the security-relevant categories are
    marked ``dispatch_eligible`` and may therefore be dispatched.
    """
    sources: list[SkillSource] = []
    if violin_skills is not None:
        sources.append(
            SkillSource(label="violin", root=violin_skills, dispatch_eligible=True)
        )
    for pattern, eligible in (
        ("security/**/SKILL.md", True),
        ("web/**/SKILL.md", True),
        ("software-development/**/SKILL.md", True),
        ("autonomous-ai-agents/**/SKILL.md", True),
        ("**/SKILL.md", False),
    ):
        sources.append(
            SkillSource(
                label="hermes",
                root=HERMES_SKILLS,
                pattern=pattern,
                dispatch_eligible=eligible,
            )
        )
    sources.append(
        SkillSource(label="strix", root=STRIX_SKILLS, pattern="**/*.md", dispatch_eligible=True)
    )
    sources.append(
        SkillSource(
            label="strix", root=STRIX_REPO_SKILLS, pattern="**/SKILL.md", dispatch_eligible=True
        )
    )
    return sources


@dataclass
class BuildReport:
    """Outcome of an index build."""

    built: bool
    reason: str
    skills: int = 0
    eligible: int = 0
    dim: int = 0
    provider: str = ""
    seconds: float = 0.0
    pool_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "built": self.built,
            "reason": self.reason,
            "skills": self.skills,
            "eligible": self.eligible,
            "dim": self.dim,
            "provider": self.provider,
            "seconds": round(self.seconds, 2),
            "pool_digest": self.pool_digest[:16],
        }


def _violin_skills_root() -> Path:
    """Locate the Violin's own skills directory for the running profile."""
    home = os.environ.get("HERMES_HOME", "").strip()
    roots: list[Path] = []
    if home:
        roots.append(Path(home).expanduser() / "profiles" / "violin" / "skills")
        roots.append(Path(home).expanduser() / "skills")
    roots.append(Path.home() / ".hermes" / "profiles" / "violin" / "skills")
    roots.append(Path.home() / ".hermes" / "skills")
    for root in roots:
        if root.is_dir():
            return root
    return roots[0]


def collect_pool(violin_skills: Path | None = None) -> list[SkillEntry]:
    """Gather every indexable skill from the configured sources.

    The profile's own skills are part of the pool by default: without them
    the routing tables reference playbooks the search cannot find.
    """
    sources = default_sources(violin_skills or _violin_skills_root())
    return collect_entries(sources)


def _batches(entries: list, max_items: int = 16, max_chars: int = 24000) -> list[list]:
    """Split the pool into batches the embedding endpoint accepts.

    The endpoint caps the *total* tokens of a request, so a batch is bounded
    by item count and by the combined size of its inputs.
    """
    batches: list[list] = []
    current: list = []
    current_chars = 0
    for entry in entries:
        size = len(entry.embed_text())
        if current and (len(current) >= max_items or current_chars + size > max_chars):
            batches.append(current)
            current = []
            current_chars = 0
        current.append(entry)
        current_chars += size
    if current:
        batches.append(current)
    return batches


def _warmup(embedder: object) -> None:
    """Pay the embedding provider's cold start once, before the batch loop."""
    try:
        embedder.embed(["warmup"])  # type: ignore[attr-defined]
    except Exception:
        # A failed warm-up is not fatal: the batch loop reports the real error.
        return


def build_index(
    force: bool = False,
    violin_skills: Path | None = None,
    provider: str = "auto",
) -> BuildReport:
    """Build or refresh the skill index.

    The rebuild is skipped when the pool digest is unchanged, so this is safe
    to call at the start of an engagement.
    """
    started = time.time()
    entries = collect_pool(violin_skills)
    if not entries:
        return BuildReport(
            built=False, reason="no skills found in the configured pools", seconds=0.0
        )
    digest = pool_digest(entries)
    index = SkillIndex()
    index.connect()
    if not force and index.get_meta("pool_digest") == digest and index.count() > 0:
        return BuildReport(
            built=False,
            reason="index already matches the current skill pool",
            skills=index.count(),
            seconds=time.time() - started,
            pool_digest=digest,
        )
    try:
        embedder = build_embedder(provider)
    except EmbeddingError as exc:
        return BuildReport(
            built=False, reason=f"no embedding backend: {exc}", seconds=time.time() - started
        )
    index.reset()
    dim = 0
    provider_name = ""
    # The free embedding tier answers 504 while its worker cold-starts. A tiny
    # warm-up call pays that cost once instead of once per batch.
    _warmup(embedder)
    for chunk in _batches(entries):
        vectors = embedder.embed([entry.embed_text() for entry in chunk])
        for entry, vector in zip(chunk, vectors):
            index.store(entry, vector.values)
            dim = dim or len(vector)
            provider_name = provider_name or vector.provider
    index.set_meta("pool_digest", digest)
    index.set_meta("index_version", str(1))
    index.set_meta("built_at", str(time.time()))
    index.set_meta("dim", str(dim))
    index.set_meta("provider", provider_name)
    index.close()
    eligible = sum(1 for entry in entries if entry.dispatch_eligible)
    return BuildReport(
        built=True,
        reason="index rebuilt",
        skills=len(entries),
        eligible=eligible,
        dim=dim,
        provider=provider_name,
        seconds=time.time() - started,
        pool_digest=digest,
    )


def index_status() -> dict[str, Any]:
    """Current state of the index."""
    index = SkillIndex()
    index.connect()
    status = {
        "path": str(index.path),
        "skills": index.count(),
        "pool_digest": index.get_meta("pool_digest")[:16],
        "built_at": index.get_meta("built_at"),
        "dim": index.get_meta("dim"),
        "provider": index.get_meta("provider"),
        "index_dir": str(default_index_dir()),
    }
    index.close()
    return status
