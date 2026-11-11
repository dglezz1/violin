"""Dispatch queue: one stream for regex and embedding origins."""

from __future__ import annotations

import json

from plugins.violin_router.core.dispatch import DispatchItem, DispatchQueue


def _item(trigger: str, origin: str = "regex", score: float = 1.0) -> DispatchItem:
    return DispatchItem(
        trigger=trigger,
        kind="vuln",
        origin=origin,
        score=score,
        signal="SQLSTATE[42000]",
        skills=["web-app"],
        labels=["SQL error"],
        exec_ref="exec-1",
    )


def test_queue_persists_and_reloads(tmp_path) -> None:
    path = tmp_path / "queue.jsonl"
    queue = DispatchQueue(path)
    queue.add(_item("sqli"))
    reloaded = DispatchQueue(path)
    items = reloaded.load()
    assert len(items) == 1
    assert items[0].trigger == "sqli"


def test_queue_collapses_the_same_trigger(tmp_path) -> None:
    queue = DispatchQueue(tmp_path / "queue.jsonl")
    first = queue.add(_item("sqli"))
    second = queue.add(_item("sqli"))
    assert first is second
    assert len(queue.pending()) == 1


def test_queue_keeps_the_stronger_score(tmp_path) -> None:
    queue = DispatchQueue(tmp_path / "queue.jsonl")
    queue.add(_item("ssti", origin="regex", score=1.0))
    queue.add(_item("ssti", origin="embedding", score=0.81))
    pending = queue.pending()
    assert len(pending) == 1
    assert pending[0].score == 1.0


def test_note_states_origin_and_required_action() -> None:
    note = _item("sqli").note()
    assert "[SKILL DISPATCH]" in note
    assert "origen: regex" in note
    assert "clase candidata: sqli" in note
    assert "violin_skill_view" in note
    assert "vuln_class=sqli" in note


def test_note_reports_the_embedding_score() -> None:
    note = _item("ssti", origin="embedding", score=0.81).note()
    assert "origen: embedding" in note
    assert "0.81" in note


def test_delivered_items_leave_the_pending_set(tmp_path) -> None:
    queue = DispatchQueue(tmp_path / "queue.jsonl")
    item = queue.add(_item("sqli"))
    assert queue.pending()
    queue.mark_delivered(item)
    assert not queue.pending()
    assert DispatchQueue(tmp_path / "queue.jsonl").load()[0].delivered is True


def test_queue_file_is_valid_jsonl(tmp_path) -> None:
    path = tmp_path / "queue.jsonl"
    queue = DispatchQueue(path)
    queue.add(_item("sqli"))
    queue.add(_item("ssrf"))
    for line in path.read_text(encoding="utf-8").splitlines():
        payload = json.loads(line)
        assert payload["trigger"]
