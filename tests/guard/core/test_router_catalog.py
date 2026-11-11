"""Skill pool catalog: discovery, deduplication and eligibility."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_router.core.catalog import (
    SkillSource,
    collect_entries,
    pool_digest,
)


def _write_skill(root: Path, category: str, name: str, description: str) -> Path:
    directory = root / category / name
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "SKILL.md"
    path.write_text(
        f"---\nname: {name}\ndescription: {description}\nplatforms: [linux]\n---\n\n# {name}\n",
        encoding="utf-8",
    )
    return path


def test_entries_carry_frontmatter_metadata(tmp_path) -> None:
    _write_skill(tmp_path, "security", "web-pentest", "How to test a web app")
    entries = collect_entries([SkillSource(label="hermes", root=tmp_path)])
    assert len(entries) == 1
    entry = entries[0]
    assert entry.name == "web-pentest"
    assert entry.description == "How to test a web app"
    assert entry.category == "security"
    assert entry.path.is_file()


def test_a_skill_matched_by_two_patterns_is_kept_once(tmp_path) -> None:
    _write_skill(tmp_path, "security", "web-pentest", "desc")
    entries = collect_entries(
        [
            SkillSource(label="hermes", root=tmp_path, pattern="security/**/SKILL.md"),
            SkillSource(label="hermes", root=tmp_path, pattern="**/SKILL.md", dispatch_eligible=True),
        ]
    )
    assert len(entries) == 1
    assert entries[0].dispatch_eligible is True


def test_embed_text_carries_identity_and_a_bounded_excerpt(tmp_path) -> None:
    path = _write_skill(tmp_path, "security", "web-pentest", "Short description")
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n# Heading\n"
        + "Real prose about testing. " * 200
        + "\nLONG BODY " * 500,
        encoding="utf-8",
    )
    entries = collect_entries([SkillSource(label="hermes", root=tmp_path)])
    text = entries[0].embed_text()
    assert "web-pentest" in text
    assert "Short description" in text
    # The excerpt gives the retrieval signal, and it is bounded.
    assert "Real prose about testing" in text
    assert len(text) <= 4000
    # The bulk of the body is not embedded.
    assert text.count("LONG BODY") < 10


def test_pool_digest_changes_with_content(tmp_path) -> None:
    path = _write_skill(tmp_path, "security", "web-pentest", "desc")
    entries = collect_entries([SkillSource(label="hermes", root=tmp_path)])
    first = pool_digest(entries)
    path.write_text(path.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
    entries = collect_entries([SkillSource(label="hermes", root=tmp_path)])
    assert pool_digest(entries) != first


def test_missing_root_yields_no_entries(tmp_path) -> None:
    entries = collect_entries([SkillSource(label="hermes", root=tmp_path / "absent")])
    assert entries == []
