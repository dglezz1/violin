"""Two-level scanner: regex first, embedding as the fallback.

Regex is cheap and deterministic. When it finds nothing, the snippet is
embedded and compared against the skill index, which catches the vocabulary a
fixed table cannot enumerate (a WAF banner, a framework-specific error).

Both levels write into the same dispatch queue and carry their origin, so a
semantic hit is as traceable as a literal one.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from .dispatch import DispatchItem, DispatchQueue
from .embedding import EmbeddingError, build_embedder
from .index import SkillIndex
from .triggers import Trigger, load_triggers, scan_text

# Outputs that are worth scanning: the target-facing execution tools.
TARGET_TOOLS = {"violin_exec", "violin_exec_burst"}
SNIPPET_WINDOW = 512
MAX_TEXT = 20000

# Confidence bands per phase. A detection inside the grey band is never
# auto-injected: it goes to review instead.
THRESHOLDS = {
    "recon": {"high": 0.80, "grey": 0.68},
    "active": {"high": 0.72, "grey": 0.60},
}
DEFAULT_THRESHOLDS = THRESHOLDS["active"]


@dataclass
class ScanResult:
    """What one scan produced."""

    detections: list[DispatchItem]
    scanned: bool = False
    source: str = ""
    grey: list[DispatchItem] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.grey is None:
            self.grey = []


def _phase_thresholds(phase: str | None) -> dict[str, float]:
    key = (phase or "active").strip().lower()
    for name, bands in THRESHOLDS.items():
        if key.startswith(name):
            return bands
    if key in {"f2", "recon_pasivo", "passive"}:
        return THRESHOLDS["recon"]
    return DEFAULT_THRESHOLDS


def _clean_text(text: str) -> str:
    return text[:MAX_TEXT]


def _snippet(text: str, offset: int, length: int) -> str:
    start = max(0, offset - SNIPPET_WINDOW // 2)
    return text[start : start + SNIPPET_WINDOW]


def regex_detections(text: str) -> list[tuple[Trigger, str]]:
    """Deterministic detections from the trigger table."""
    triggers = load_triggers()
    return scan_text(text, triggers)


def semantic_detections(
    text: str,
    top_k: int = 3,
    high: float = 0.72,
    grey: float = 0.60,
) -> tuple[list[tuple[str, float, str]], list[tuple[str, float, str]]]:
    """Return (confirmed, grey) semantic detections over the skill index."""
    index = SkillIndex()
    index.connect()
    if index.count() == 0:
        index.close()
        return [], []
    try:
        embedder = build_embedder(os.environ.get("VIOLIN_EMBED_PROVIDER", "auto"))
        vectors = embedder.embed([text])
    except EmbeddingError:
        index.close()
        return [], []
    if not vectors:
        index.close()
        return [], []
    hits = index.search(
        vectors[0].values, top_k=top_k, eligible_only=True, query_text=text[:512]
    )
    index.close()
    confirmed: list[tuple[str, float, str]] = []
    grey_band: list[tuple[str, float, str]] = []
    for hit in hits:
        item = (hit.name, hit.score, hit.category)
        if hit.score >= high:
            confirmed.append(item)
        elif hit.score >= grey:
            grey_band.append(item)
    return confirmed, grey_band


def scan_tool_result(
    tool_name: str,
    result: Any,
    exec_ref: str = "",
    session_id: str = "",
    phase: str | None = None,
) -> ScanResult:
    """Scan one tool result and queue everything it reveals."""
    if tool_name not in TARGET_TOOLS:
        return ScanResult(detections=[])
    text = _clean_text(result if isinstance(result, str) else str(result))
    if not text.strip():
        return ScanResult(detections=[])
    queue = DispatchQueue()
    queue.load()
    detections: list[DispatchItem] = []
    hits = regex_detections(text)
    for trigger, snippet in hits:
        item = DispatchItem(
            trigger=trigger.name,
            kind=trigger.kind,
            origin="regex",
            score=1.0,
            signal=snippet[:200],
            skills=list(trigger.skills),
            labels=list(trigger.labels),
            exec_ref=exec_ref,
            session_id=session_id,
            created_at=_now(),
        )
        detections.append(queue.add(item))
    if hits:
        return ScanResult(detections=detections, scanned=True, source="regex")
    bands = _phase_thresholds(phase)
    confirmed, grey = semantic_detections(
        text, high=bands["high"], grey=bands["grey"]
    )
    for name, score, category in confirmed:
        item = DispatchItem(
            trigger=category or name,
            kind="vuln",
            origin="embedding",
            score=score,
            signal=_snippet(text, 0, SNIPPET_WINDOW)[:200],
            skills=[name],
            labels=[category] if category else [],
            exec_ref=exec_ref,
            session_id=session_id,
            created_at=_now(),
        )
        detections.append(queue.add(item))
    return ScanResult(
        detections=detections,
        scanned=True,
        source="embedding" if confirmed else "",
        grey=[
            DispatchItem(
                trigger=category or name,
                kind="vuln",
                origin="embedding",
                score=score,
                signal="",
                skills=[name],
                labels=[category] if category else [],
                exec_ref=exec_ref,
                session_id=session_id,
                created_at=_now(),
            )
            for name, score, category in grey
        ],
    )


def _now() -> float:
    import time

    return time.time()
