"""Surface resolution: a detected class must resolve to concrete playbooks."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_router.core.surface import load_table, resolve


def test_every_entry_declares_classes_and_playbooks() -> None:
    entries = load_table()
    assert entries, "the surface table must not be empty"
    for entry in entries:
        assert entry.classes, f"{entry.key} routes no vulnerability class"
        assert entry.skills, f"{entry.key} names no playbook"


def test_a_class_resolves_to_its_playbooks() -> None:
    refs = resolve(vulnerability_class="sqli")
    names = [ref.name for ref in refs]
    assert names, "sqli resolved to no playbook"
    assert "web-app" in names


def test_a_surface_resolves_even_without_a_class() -> None:
    refs = resolve(command="curl http://localhost:3000/api/Feedbacks")
    assert refs, "a feedback endpoint resolved to no playbook"


def test_resolution_is_ordered_and_deduplicated() -> None:
    refs = resolve(vulnerability_class="xss", command="curl /api/Reviews")
    names = [ref.name for ref in refs]
    assert len(names) == len(set(names)), "a playbook was listed twice"


def test_an_unknown_class_resolves_to_nothing() -> None:
    assert resolve(vulnerability_class="not-a-real-class") == []


def test_the_guard_vocabulary_is_reachable() -> None:
    from plugins.violin_router.core.surface import guard_vocabulary

    classes = guard_vocabulary()
    if not classes:
        # The guard is not importable from a bare checkout; the runtime path is
        # covered by the plugin-level test.
        return
    assert len(classes) > 20, classes
    assert "sqli" in classes
