"""Typed tool schemas for the violin_guard plugin using Pydantic v2."""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

from ..core.engagement import state
from .schema_execution import (
    ExecArgsModel,
    ExecBurstArgsModel,
    ExecCancelArgsModel,
    ExecStatusArgsModel,
    HeartbeatDoneArgsModel,
    RebindPendingBatchArgsModel,
    StatusArgsModel,
    TargetArgsModel,
)
from .schema_findings import (
    FindingClaimModel as FindingClaimModel,
)
from .schema_findings import (
    FindingRecordModel as FindingRecordModel,
)
from .schema_findings import (
    SubmitFindingArgsModel,
)
from .schema_tasks import (
    RecordHypothesisArgsModel,
    RecordPttArgsModel,
    ReviewBatchArgsModel,
)

T = TypeVar("T", bound=BaseModel)


def _normalize_evidence_outputs(raw: Any) -> Any:
    """Accept the list-of-strings shape, and the nested one a model sometimes sends.

    A model that renders ``evidence_outputs`` as ``[{"item": "evidence/x"}]``
    means the same thing as ``["evidence/x"]``. Normalising it here keeps a
    cosmetic mistake from costing a turn, and keeps the paths themselves
    validated by the field type afterwards.
    """
    if not isinstance(raw, list):
        return raw
    normalized: list[str] = []
    for entry in raw:
        if isinstance(entry, str):
            normalized.append(entry)
        elif isinstance(entry, dict):
            for key in ("item", "path", "file", "name"):
                value = entry.get(key)
                if isinstance(value, str) and value:
                    normalized.append(value)
                    break
            else:
                # An entry with no recognisable path is a real mistake; leave it
                # to the field validation to reject.
                normalized.append(entry)
        else:
            normalized.append(entry)
    return normalized


def validate_args(model_cls: type[T], raw_args: dict[str, Any] | None, *, strict: bool = True) -> T:
    """Validate raw payload dictionary using Pydantic model."""
    payload = dict(raw_args or {})
    if "evidence_outputs" in payload:
        payload["evidence_outputs"] = _normalize_evidence_outputs(payload["evidence_outputs"])
    return model_cls.model_validate(payload, strict=strict)


def to_tool_schema(
    model_cls: type[BaseModel],
    description: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """Dynamically export tool schema directly from Pydantic model_json_schema()."""
    schema = model_cls.model_json_schema()
    model_description = schema.pop("description", "")
    doc = description or model_description or (model_cls.__doc__ or "")
    schema.pop("title", None)

    if "properties" in schema:
        for prop in schema["properties"].values():
            if isinstance(prop, dict):
                prop.pop("title", None)

    res: dict[str, Any] = {"description": doc, "parameters": schema}
    if name:
        res["name"] = name
    return res


# Dynamic Tool Schemas (Derived directly from Pydantic models via native model_json_schema)

RECORD_PTT_SCHEMA = to_tool_schema(RecordPttArgsModel)
RECORD_HYPOTHESIS_SCHEMA = to_tool_schema(RecordHypothesisArgsModel)
SUBMIT_FINDING_SCHEMA = to_tool_schema(SubmitFindingArgsModel)
EXEC_SCHEMA = to_tool_schema(ExecArgsModel)
REVIEW_BATCH_SCHEMA = to_tool_schema(ReviewBatchArgsModel)
REBIND_PENDING_BATCH_SCHEMA = to_tool_schema(RebindPendingBatchArgsModel)
HEARTBEAT_DONE_SCHEMA = to_tool_schema(
    HeartbeatDoneArgsModel,
    description=(
        f"Call AFTER heartbeat review. Required clear sequence: 1) violin_status -> 2) violin_review_batch "
        f"(if pending batch exists) -> 3) violin_heartbeat_done(eng_dir=...). Re-read skills/pentest/SKILL.md "
        f"and review scope.yaml / state/ptt.md / hypotheses.md / state/history.md. Cadence is {state.COMMAND_INTERVAL}"
        " executed target commands; exploitation/post-exploitation/PRIVESC/FLAGS suppress"
        " heartbeat. Clears heartbeat lock so violin_exec may release the next command."
    ),
)
EXEC_BURST_SCHEMA = to_tool_schema(ExecBurstArgsModel, name="violin_exec_burst")
EXEC_STATUS_SCHEMA = to_tool_schema(ExecStatusArgsModel)
EXEC_CANCEL_SCHEMA = to_tool_schema(ExecCancelArgsModel)
TARGET_SCHEMA = to_tool_schema(TargetArgsModel, name="violin_target")
STATUS_SCHEMA = to_tool_schema(StatusArgsModel, name="violin_status")
