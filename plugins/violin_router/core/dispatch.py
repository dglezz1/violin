"""Dispatch queue: one stream for regex and embedding detections.

A detection is never silently dropped. Each one carries its origin
(``regex`` or ``embedding``) so the receipt trail records which mechanism
produced it, and each one maps to the skill set that must be consulted before
the class is tested.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DISPATCH_VERSION = 1


def _queue_path() -> Path:
    override = os.environ.get("VIOLIN_ROUTER_HOME", "").strip()
    if override:
        base = Path(override).expanduser()
    else:
        home = os.environ.get("HERMES_HOME", "").strip()
        base = Path(home).expanduser() if home else Path.home() / ".hermes"
        base = base / "violin-router"
    return base / "dispatch_queue.jsonl"


@dataclass
class DispatchItem:
    """One detection queued for the model."""

    trigger: str
    kind: str = "vuln"
    origin: str = "regex"
    score: float = 1.0
    signal: str = ""
    skills: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    exec_ref: str = ""
    session_id: str = ""
    created_at: float = 0.0
    delivered: bool = False

    def key(self) -> str:
        """Identity of a detection: the class it names, not the mechanism.

        A regex hit and a semantic hit on the same class are one detection;
        the origin is recorded, not used to split them.
        """
        return self.trigger

    def note(self) -> str:
        """The compact block injected into the model's turn."""
        origin = (
            f"regex (patrón: {self.signal!r})"
            if self.origin == "regex"
            else f"embedding (score {self.score:.2f}, sin match regex previo)"
        )
        lines = [
            "[SKILL DISPATCH]",
            f"origen: {origin}",
        ]
        if self.signal:
            lines.append(f"señal: {self.signal}")
        lines.append(f"clase candidata: {self.trigger}")
        if self.skills:
            lines.append(f"skills: {' · '.join(self.skills)}")
        lines.append(
            "acción requerida: antes de testear esta clase, registrar vuln_class="
            f"{self.trigger} en el PTT y ejecutar violin_skill_view sobre una de las "
            "skills listadas."
        )
        lines.append(
            "El gate rechazará cualquier comando de testing en esta clase si no hay "
            "skill vinculada en el PTT."
        )
        return "\n".join(lines)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class DispatchQueue:
    """Append-only queue persisted next to the index."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or _queue_path()
        self._lock = threading.RLock()
        self._items: list[DispatchItem] = []

    def load(self) -> list[DispatchItem]:
        with self._lock:
            self._items = []
            if not self.path.is_file():
                return self._items
            try:
                for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._items.append(DispatchItem(**json.loads(line)))
                    except (json.JSONDecodeError, TypeError):
                        continue
            except OSError:
                return self._items
            return self._items

    def add(self, item: DispatchItem) -> DispatchItem:
        """Queue a detection, collapsing duplicates of the same trigger.

        A deterministic hit wins over a semantic one at equal confidence: the
        regex layer is the stronger signal, so it is the one that is kept
        when both fire on the same class.
        """
        with self._lock:
            if not self._items:
                self.load()
            for existing in self._items:
                if existing.key() == item.key() and not existing.delivered:
                    if (item.score, item.origin == "regex") > (
                        existing.score,
                        existing.origin == "regex",
                    ):
                        existing.score = item.score
                        existing.origin = item.origin
                        existing.signal = item.signal or existing.signal
                        existing.skills = item.skills or existing.skills
                        existing.labels = item.labels or existing.labels
                    return existing
            self._items.append(item)
            self._append(item)
            return item

    def _append(self, item: DispatchItem) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(item.as_dict(), ensure_ascii=False) + "\n")
        except OSError:
            pass

    def pending(self) -> list[DispatchItem]:
        with self._lock:
            if not self._items:
                self.load()
            return [item for item in self._items if not item.delivered]

    def mark_delivered(self, item: DispatchItem) -> None:
        with self._lock:
            item.delivered = True
            self._rewrite()

    def _rewrite(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = "\n".join(
                json.dumps(item.as_dict(), ensure_ascii=False) for item in self._items
            )
            self.path.write_text(payload + ("\n" if payload else ""), encoding="utf-8")
        except OSError:
            pass

    def clear(self) -> None:
        with self._lock:
            self._items = []
            try:
                self.path.unlink()
            except OSError:
                pass
