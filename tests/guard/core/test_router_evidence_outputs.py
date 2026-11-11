"""Evidence-output normalisation: a cosmetic shape must not cost a turn."""

from __future__ import annotations

from plugins.violin_guard.core.schemas import _normalize_evidence_outputs, validate_args
from plugins.violin_guard.core.schema_execution import ExecArgsModel


def test_a_flat_list_is_unchanged() -> None:
    assert _normalize_evidence_outputs(["evidence/a.txt", "evidence/b.txt"]) == [
        "evidence/a.txt",
        "evidence/b.txt",
    ]


def test_a_nested_entry_becomes_its_path() -> None:
    assert _normalize_evidence_outputs([{"item": "evidence/a.txt"}]) == ["evidence/a.txt"]


def test_other_nested_keys_are_accepted() -> None:
    assert _normalize_evidence_outputs([{"path": "evidence/a.txt"}]) == ["evidence/a.txt"]
    assert _normalize_evidence_outputs([{"file": "evidence/a.txt"}]) == ["evidence/a.txt"]
    assert _normalize_evidence_outputs([{"name": "evidence/a.txt"}]) == ["evidence/a.txt"]


def test_a_mixed_list_is_normalised() -> None:
    assert _normalize_evidence_outputs(["evidence/a.txt", {"item": "evidence/b.txt"}]) == [
        "evidence/a.txt",
        "evidence/b.txt",
    ]


def test_an_unrecognisable_entry_is_left_to_the_field_validation() -> None:
    assert _normalize_evidence_outputs([{"unrelated": 1}]) == [{"unrelated": 1}]


def test_validate_args_accepts_the_nested_shape() -> None:
    model = validate_args(
        ExecArgsModel,
        {
            "eng_dir": "/tmp/eng",
            "command": "curl http://x",
            "target": "x",
            "phase": "RECON",
            "evidence_outputs": [{"item": "evidence/a.txt"}],
        },
    )
    assert model.evidence_outputs == ["evidence/a.txt"]


def test_validate_args_still_rejects_a_bad_path() -> None:
    """The path rules live in the executor, not in the schema."""
    from pathlib import Path

    import pytest

    from plugins.violin_guard.engine.execution_support import _validate_evidence_outputs

    with pytest.raises(ValueError):
        _validate_evidence_outputs(Path("/tmp/eng"), ["../escape.txt"])


def test_a_nested_path_still_reaches_the_path_rules() -> None:
    """Normalisation must not become a way around the executor's checks."""
    from pathlib import Path

    import pytest

    from plugins.violin_guard.engine.execution_support import _validate_evidence_outputs

    model = validate_args(
        ExecArgsModel,
        {
            "eng_dir": "/tmp/eng",
            "command": "curl http://x",
            "target": "x",
            "phase": "RECON",
            "evidence_outputs": [{"item": "../escape.txt"}],
        },
    )
    with pytest.raises(ValueError):
        _validate_evidence_outputs(Path("/tmp/eng"), model.evidence_outputs)
