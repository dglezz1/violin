"""Skill pool discovery for the Violin semantic router.

The router indexes playbooks from several local sources so that one search
reaches security guidance authored for Hermes, Strix, Dark-Moon and Violin.
Only the *frontmatter* of a skill (name, description, tags) is embedded; the
body stays on disk and is delivered on demand through the engine's skill view.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
# Some skills (the Hermes "claude-code-imports" set) open a frontmatter block
# and never close it: the body simply follows the last key. The parser accepts
# that shape so those playbooks keep their description instead of indexing as
# an anonymous entry.
OPEN_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n(?=\s*#|\Z)", re.DOTALL)
_KEY_RE = re.compile(r"^([A-Za-z0-9_.-]+):\s*(.*)$")


@dataclass(frozen=True)
class SkillEntry:
    """One indexable playbook."""

    name: str
    description: str
    path: Path
    source: str
    category: str = ""
    tags: tuple[str, ...] = ()
    dispatch_eligible: bool = False
    excerpt: str = ""
    use_when: str = ""
    avoid_when: str = ""

    @property
    def body_path(self) -> Path:
        return self.path

    def embed_text(self) -> str:
        """Text handed to the embedding model.

        The name, the description, the tags and a short excerpt of the body
        give the retrieval enough signal to tell two playbooks apart. The
        excerpt opens with the titles of the playbooks the skill carries, so
        a short skill still names the techniques it owns. The excerpt is
        computed once at build time: the body itself never enters a prompt.
        """
        parts = [self.name.replace("/", " "), self.description]
        if self.tags:
            parts.append(" ".join(self.tags))
        if self.excerpt:
            parts.append(self.excerpt)
        return " | ".join(p for p in parts if p)[:4000]

    def content_digest(self) -> str:
        try:
            return hashlib.sha256(self.path.read_bytes()).hexdigest()
        except OSError:
            return ""


@dataclass
class SkillSource:
    """A root directory that contributes skills to the pool."""

    label: str
    root: Path
    pattern: str = "**/SKILL.md"
    dispatch_eligible: bool = False
    category_filter: tuple[str, ...] = field(default_factory=tuple)


def _parse_frontmatter(text: str) -> dict[str, str]:
    match = FRONTMATTER_RE.match(text) or OPEN_FRONTMATTER_RE.match(text)
    if not match:
        return {}
    block = match.group(1)
    data: dict[str, str] = {}
    key: str | None = None
    for raw in block.splitlines():
        if not raw.strip():
            continue
        if raw.startswith((" ", "\t", "-")) and key:
            value = raw.strip().lstrip("-").strip()
            if value:
                data[key] = f"{data.get(key, '')} {value}".strip()
            continue
        entry = _KEY_RE.match(raw)
        if entry:
            key = entry.group(1)
            data[key] = entry.group(2).strip().strip("\"'")
        else:
            key = None
    return data


def _tags_of(raw: str | None) -> tuple[str, ...]:
    """First-class tags only: a nested metadata blob is not a tag list."""
    if not raw:
        return ()
    cleaned = raw.strip().strip("[]")
    tags = []
    for tag in cleaned.split(","):
        tag = tag.strip().strip("\"'")
        if not tag or len(tag) > 40:
            continue
        if ":" in tag or "[" in tag or tag.endswith(":"):
            continue
        tags.append(tag)
    return tuple(tags)


def _category_for(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return ""
    parts = relative.parts
    return parts[0] if len(parts) > 2 else ""


_WHEN_HINTS = ("when to use", "use when", "use this", "when not", "avoid", "do not use", "not for")


def _playbook_titles(path: Path) -> str:
    """The playbook titles a skill ships, as retrieval signal.

    A skill whose body is short (Violin's routed skills are) still owns real
    ground: the playbooks it carries. Their titles name the techniques inside
    ("SQL injection", "path traversal") and lift the skill for exactly the
    queries those techniques describe.
    """
    try:
        playbooks = sorted((path.parent / "playbooks").glob("*.md"))
    except OSError:
        return ""
    titles = []
    for playbook in playbooks[:20]:
        for line in playbook.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("#") and len(line) > 3:
                titles.append(line.lstrip("#").strip())
                break
    return " ".join(titles)[:400]


def _when_sections(text: str) -> tuple[str, str]:
    """Use-when / avoid-when hints from the body's own headings (L1 signal)."""
    body = FRONTMATTER_RE.sub("", text, count=1)
    if body == text:
        body = OPEN_FRONTMATTER_RE.sub("", text, count=1)
    use_when = ""
    avoid_when = ""
    section = ""
    for raw in body.splitlines():
        line = raw.strip().lower()
        if line.startswith("#"):
            title = line.lstrip("#").strip()
            if any(h in title for h in _WHEN_HINTS):
                section = "avoid" if ("avoid" in title or "not" in title) else "use"
            elif section:
                section = ""
            continue
        if section and line and not line.startswith(("|", "```")):
            if section == "use" and len(use_when) < 300:
                use_when = f"{use_when} {raw.strip()}".strip()
            elif section == "avoid" and len(avoid_when) < 300:
                avoid_when = f"{avoid_when} {raw.strip()}".strip()
    return use_when[:300], avoid_when[:300]


def _excerpt_of(text: str, limit: int = 1200) -> str:
    """A short, plain-text excerpt of a skill body.

    Headings are dropped and the prose is kept: the excerpt exists to give the
    retrieval signal ("what this playbook covers"), not to be read.
    """
    body = FRONTMATTER_RE.sub("", text, count=1)
    if body == text:
        body = OPEN_FRONTMATTER_RE.sub("", text, count=1)
    lines: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "```", "---", "<!--")):
            continue
        if line.startswith("|") or line.startswith("- ") and len(line) < 4:
            continue
        lines.append(line)
        if sum(len(item) for item in lines) >= limit:
            break
    return " ".join(lines)[:limit]


def _iter_source(source: SkillSource) -> Iterator[SkillEntry]:
    if not source.root.is_dir():
        return
    for path in sorted(source.root.glob(source.pattern)):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        front = _parse_frontmatter(text)
        name = (front.get("name") or path.parent.name).strip()
        description = (front.get("description") or "").strip()
        category = _category_for(path, source.root)
        if source.category_filter and category not in source.category_filter:
            continue
        eligible = source.dispatch_eligible
        if source.label == "violin" and category in {"pentest", "web-app"}:
            eligible = True
        use_when, avoid_when = _when_sections(text)
        playbook_signal = _playbook_titles(path)
        excerpt = _excerpt_of(text)
        if playbook_signal:
            excerpt = f"{playbook_signal} | {excerpt}"[:1200]
            # A one-line description cannot carry what a routed skill owns;
            # the playbook titles are the skill's own words for it.
            if len(description) < 80 and playbook_signal:
                description = f"{description} Covers: {playbook_signal[:180]}"
        yield SkillEntry(
            name=name,
            description=description,
            path=path,
            source=source.label,
            category=category,
            tags=_tags_of(front.get("tags") or front.get("metadata")),
            dispatch_eligible=eligible,
            excerpt=excerpt,
            use_when=use_when,
            avoid_when=avoid_when,
        )


def collect_entries(sources: Iterable[SkillSource]) -> list[SkillEntry]:
    """Merge every source into one deduplicated, stable-ordered pool.

    A skill that several patterns match (the broad pattern and a narrow one)
    is kept once, and it stays dispatch-eligible when any matching source
    marked it so. The same playbook present under two roots (a local copy and
    a checkout of it) is one entry as well: the identity is the skill's own
    content, not the path it was found under.
    """
    merged: dict[str, SkillEntry] = {}
    by_content: dict[str, str] = {}
    for source in sources:
        for entry in _iter_source(source):
            digest = entry.content_digest()
            key = by_content.get(digest)
            if key is not None:
                existing = merged[key]
                if source.dispatch_eligible and not existing.dispatch_eligible:
                    merged[key] = SkillEntry(
                        name=existing.name,
                        description=existing.description,
                        path=existing.path,
                        source=existing.source,
                        category=existing.category,
                        tags=existing.tags,
                        dispatch_eligible=True,
                        excerpt=existing.excerpt,
                        use_when=existing.use_when,
                        avoid_when=existing.avoid_when,
                    )
                continue
            path_key = f"{source.label}:{entry.path}"
            merged[path_key] = entry
            by_content[digest] = path_key
    return sorted(merged.values(), key=lambda e: (e.source, e.category, e.name))


def pool_digest(entries: Iterable[SkillEntry]) -> str:
    """Content hash of the pool: the index is rebuilt only when it changes.

    The hash covers the text that is actually embedded, not only the file
    bytes, so a change in how the frontmatter is parsed rebuilds the index
    instead of leaving a stale one behind.
    """
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda e: (e.source, e.path.as_posix())):
        digest.update(entry.path.as_posix().encode())
        digest.update(b"\0")
        digest.update(entry.embed_text().encode())
        digest.update(b"\0")
    return digest.hexdigest()
