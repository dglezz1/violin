"""Objective-catalogue detection: recognise the target's own work queue.

Some targets publish a record of their own objectives — a collection of
entries each carrying a name, a description and an explicit state. When a
target does, the record is the work queue and the target's state is the only
verdict (`skills/pentest/references/objective-catalogue.md`). The detection
here is mechanical: it fires on the shape of the response, not on a route
name, so it works on any target that publishes such a record — without the
operator having to ask for it.
"""

from __future__ import annotations

import json
import re
from typing import Any

STATE_KEYS = ("solved", "done", "completed", "captured", "achieved")
NAME_KEYS = ("name", "title", "objective")
DESC_KEYS = ("description", "desc", "detail", "summary")

# A record is "stateful" when a state key holds a boolean or a canonical
# status string. The catalogue shape needs most records stateful and named.
_BOOL_RE = re.compile(r"^\s*(true|false)\s*$", re.IGNORECASE)
_STATUS_TRUE = {"solved", "done", "closed", "complete", "completed", "captured", "achieved"}
_STATUS_FALSE = {"open", "unsolved", "pending", "incomplete"}


def _record_state(record: dict[str, Any]) -> bool | None:
    for key in STATE_KEYS:
        value = record.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            norm = value.strip().lower()
            if norm in _STATUS_TRUE:
                return True
            if norm in _STATUS_FALSE:
                return False
    return None


def _first(record: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, (int, float)):
            return str(value)
    return ""


def detect_catalogue(text: str) -> list[dict[str, Any]] | None:
    """The catalogue records when *text* carries the objective shape, else None.

    The text may be a JSON document or contain one (a tool result that wraps
    the body). Both polarities of the state field must appear, or enough
    records to show the target maintains per-entry state — a single record
    that happens to have a "solved" key is not a catalogue.
    """
    if not text or ("solved" not in text and "done" not in text and "completed" not in text):
        return None
    candidates: list[list[dict[str, Any]]] = []
    for snippet in _json_candidates(text):
        data = _loads(snippet)
        if data is None:
            continue
        records = _collection(data)
        if records:
            candidates.append(records)
    for records in candidates:
        if _looks_like_catalogue(records):
            return records
    return None


def _json_candidates(text: str) -> list[str]:
    """The JSON documents inside *text* (the whole text, plus embedded ones)."""
    out = [text]
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            _obj, end = decoder.raw_decode(text[match.start() :])
        except json.JSONDecodeError:
            continue
        if end > 64:
            out.append(text[match.start() : match.start() + end])
    return out


def _loads(snippet: str) -> Any:
    try:
        return json.loads(snippet)
    except (json.JSONDecodeError, ValueError):
        return None


def _collection(data: Any) -> list[dict[str, Any]] | None:
    records: object = data
    if isinstance(records, dict):
        for key in ("data", "objectives", "challenges", "items", "results"):
            if isinstance(records.get(key), list):
                records = records[key]
                break
        else:
            return None
    if not isinstance(records, list):
        return None
    return [r for r in records if isinstance(r, dict)]


def _looks_like_catalogue(records: list[dict[str, Any]]) -> bool:
    if len(records) < 3:
        return False
    sample = records[:12]
    states = [_record_state(r) for r in sample]
    stateful = sum(1 for s in states if s is not None)
    named = sum(1 for r in sample if _first(r, NAME_KEYS))
    described = sum(1 for r in sample if _first(r, DESC_KEYS))
    both_polarities = True in states and False in states
    return (
        stateful >= max(3, len(sample) - 1)
        and named >= len(sample) - 1
        and described >= len(sample) // 2
        and both_polarities
    )


def dispatch_note() -> str:
    """The once-per-session note that hands the queue to the agent."""
    return (
        "\n[OBJECTIVE MODE] El target expone su propio registro de objetivos "
        "(una entrada por objetivo con nombre, descripción y estado). Ese "
        "registro es la cola de trabajo y su estado en el target es el único "
        "veredicto. Método (skills/pentest/references/objective-catalogue.md): "
        "1) snapshot del catálogo bajo state/ y resumen de los abiertos "
        "(scripts/sync-objectives.py del perfil, o un fetch equivalente); "
        "2) los abiertos, ordenados por dificultad del target, son la cola; "
        "3) la descripción de cada pendiente es la especificación de su "
        "trigger — deriva la acción y su vuln_class, registra la hipótesis, "
        "lee el playbook (violin_skill_search/view), ejecuta (burst si agrupa "
        "clase), y RE-SINCRONIZA: la entrada que sigue abierta no está "
        "cerrada; registra el test_command/test_response exacto y refina. "
        "4) los valores capturados van al flag register "
        "(state/flag-register.md). 5) Paced, un objetivo a la vez; blocked con "
        "el bloqueador exacto tras ~5 enfoques distintos. Nunca busques el "
        "trigger fuera del target."
    )
