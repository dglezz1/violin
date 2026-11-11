"""Objective-catalogue detection: the target's own queue, found by shape."""

from __future__ import annotations

import json

from plugins.violin_router.core.objectives import detect_catalogue, dispatch_note


def _catalogue(n: int = 6) -> str:
    entries = [
        {
            "id": i,
            "name": f"objective-{i}",
            "category": "cat",
            "description": f"do the thing {i}",
            "difficulty": (i % 6) + 1,
            "solved": i % 2 == 0,
        }
        for i in range(1, n + 1)
    ]
    return json.dumps({"status": "success", "data": entries})


def test_a_real_catalogue_is_detected() -> None:
    records = detect_catalogue(_catalogue())
    assert records is not None and len(records) == 6


def test_a_catalogue_inside_a_tool_result_is_detected() -> None:
    text = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n" + _catalogue()
    assert detect_catalogue(text) is not None


def test_single_polarity_is_not_a_catalogue() -> None:
    text = json.dumps(
        {
            "items": [
                {"name": f"x{i}", "description": "d", "solved": True} for i in range(6)
            ]
        }
    )
    assert detect_catalogue(text) is None


def test_records_without_state_are_not_a_catalogue() -> None:
    text = json.dumps(
        {"data": [{"name": f"x{i}", "description": "d"} for i in range(6)]}
    )
    assert detect_catalogue(text) is None


def test_ordinary_output_is_not_a_catalogue() -> None:
    text = 'HTTP/1.1 200 OK\n\n{"user":{"name":"x","description":"y","solved":true}}'
    assert detect_catalogue(text) is None


def test_a_two_record_catalogue_is_too_small() -> None:
    assert detect_catalogue(_catalogue(2)) is None


def test_the_dispatch_note_carries_the_method() -> None:
    note = dispatch_note()
    assert "[OBJECTIVE MODE]" in note
    assert "sync" in note or "snapshot" in note
    assert "re-sincroniza" in note or "RE-SINCRONIZA" in note
    assert "flag register" in note
