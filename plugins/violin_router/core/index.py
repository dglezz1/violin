"""Vector index over the skill pool (sqlite-vec).

The index lives outside the distributed plugin tree so that a profile update
never destroys it, and it carries the pool digest so a rebuild is only needed
when the set of skills actually changes.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .catalog import SkillEntry

_INDEX_VERSION = 1
# A literal term match is a stronger signal than a topical one, so it lifts
# the score above what the cosine similarity alone would give.
_LEXICAL_BONUS = 0.25
_STOP_TERMS = frozenset(
    {
        "a", "an", "and", "or", "the", "to", "of", "in", "for", "on", "with", "how",
        "test", "testing", "tests", "playbook", "skill", "workflow", "using", "use",
    }
)


def _terms(query: str) -> list[str]:
    """The significant terms of a query, lowercased."""
    words = [word.strip(".,:;()[]'\"").lower() for word in (query or "").split()]
    return [word for word in words if len(word) > 2 and word not in _STOP_TERMS]


def default_index_dir() -> Path:
    """Sidecar location: survives ``hermes profile update``."""
    override = os.environ.get("VIOLIN_ROUTER_HOME", "").strip()
    if override:
        return Path(override).expanduser()
    home = os.environ.get("HERMES_HOME", "").strip()
    base = Path(home).expanduser() if home else Path.home() / ".hermes"
    return base / "violin-router"


@dataclass(frozen=True)
class SearchHit:
    """One search result."""

    name: str
    description: str
    path: str
    source: str
    category: str
    score: float

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "path": self.path,
            "source": self.source,
            "category": self.category,
            "score": round(self.score, 4),
        }


class SkillIndex:
    """SQLite-backed vector index with a brute-force cosine fallback."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (default_index_dir() / "skills.vecdb")
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._vec = False

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        with self._lock:
            if self._conn is not None:
                return self._conn
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS skills (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    path TEXT NOT NULL,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    dispatch_eligible INTEGER NOT NULL,
                    embed_text TEXT NOT NULL,
                    content_digest TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS skill_vectors (
                    skill_id INTEGER PRIMARY KEY REFERENCES skills(id),
                    dim INTEGER NOT NULL,
                    vector BLOB NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            try:
                import sqlite_vec  # type: ignore

                conn.enable_load_extension(True)
                sqlite_vec.load(conn)
                conn.enable_load_extension(False)
                conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS skill_vec USING vec0("
                    "skill_id INTEGER PRIMARY KEY, embedding FLOAT[?])"
                )
                self._vec = True
            except Exception:
                self._vec = False
            self._conn = conn
            return conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # -- writing -----------------------------------------------------------
    def reset(self) -> None:
        conn = self.connect()
        with self._lock:
            conn.execute("DELETE FROM skills")
            conn.execute("DELETE FROM skill_vectors")
            try:
                conn.execute("DELETE FROM skill_vec")
            except sqlite3.OperationalError:
                pass
            conn.commit()

    def store(self, entry: SkillEntry, embedding: Sequence[float]) -> None:
        conn = self.connect()
        with self._lock:
            cur = conn.execute(
                "INSERT INTO skills (name, description, path, source, category, tags,"
                " dispatch_eligible, embed_text, content_digest)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    entry.name,
                    entry.description,
                    str(entry.path),
                    entry.source,
                    entry.category,
                    json.dumps(list(entry.tags)),
                    1 if entry.dispatch_eligible else 0,
                    entry.embed_text(),
                    entry.content_digest(),
                ),
            )
            skill_id = int(cur.lastrowid or 0)
            packed = _pack(embedding)
            conn.execute(
                "INSERT OR REPLACE INTO skill_vectors (skill_id, dim, vector) VALUES (?,?,?)",
                (skill_id, len(embedding), packed),
            )
            if self._vec:
                try:
                    conn.execute(
                        "INSERT OR REPLACE INTO skill_vec (skill_id, embedding) VALUES (?, ?)",
                        (skill_id, json.dumps(list(embedding))),
                    )
                except sqlite3.OperationalError:
                    self._vec = False
            conn.commit()

    def set_meta(self, key: str, value: str) -> None:
        conn = self.connect()
        with self._lock:
            conn.execute(
                "INSERT OR REPLACE INTO index_meta (key, value) VALUES (?,?)", (key, value)
            )
            conn.commit()

    def get_meta(self, key: str) -> str:
        conn = self.connect()
        with self._lock:
            row = conn.execute("SELECT value FROM index_meta WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else ""

    def count(self) -> int:
        conn = self.connect()
        with self._lock:
            row = conn.execute("SELECT COUNT(*) AS n FROM skills").fetchone()
        return int(row["n"]) if row else 0

    # -- reading -----------------------------------------------------------
    def search(
        self,
        embedding: Sequence[float],
        top_k: int = 3,
        eligible_only: bool = True,
        query_text: str = "",
    ) -> list[SearchHit]:
        """Rank skills by relevance against ``embedding``.

        The ranking is hybrid: the cosine similarity carries the semantic
        signal, and the query's literal terms carry the precise one. A
        playbook that literally names the technology in the query ("AWS",
        "SQL") outranks one that is merely topically close.
        """
        conn = self.connect()
        with self._lock:
            rows = conn.execute(
                "SELECT s.id, s.name, s.description, s.path, s.source, s.category,"
                " s.dispatch_eligible, v.vector, v.dim FROM skills s"
                " JOIN skill_vectors v ON v.skill_id = s.id"
            ).fetchall()
        from .embedding import cosine

        terms = _terms(query_text)
        hits: list[SearchHit] = []
        for row in rows:
            if eligible_only and not int(row["dispatch_eligible"]):
                continue
            vector = _unpack(row["vector"], int(row["dim"]))
            score = cosine(embedding, vector)
            haystack = f"{row['name']} {row['description']} {row['category']}".lower()
            matched = [term for term in terms if term in haystack]
            if matched:
                score += _LEXICAL_BONUS * (len(matched) / max(1, len(terms)))
            hits.append(
                SearchHit(
                    name=str(row["name"]),
                    description=str(row["description"]),
                    path=str(row["path"]),
                    source=str(row["source"]),
                    category=str(row["category"]),
                    score=score,
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:top_k]

    def all_entries(self) -> list[dict[str, object]]:
        conn = self.connect()
        with self._lock:
            rows = conn.execute(
                "SELECT name, description, path, source, category, dispatch_eligible FROM skills"
            ).fetchall()
        return [dict(row) for row in rows]

    def find_by_name(self, name: str) -> dict[str, object] | None:
        conn = self.connect()
        with self._lock:
            row = conn.execute(
                "SELECT name, description, path, source, category, dispatch_eligible FROM skills"
                " WHERE name=? LIMIT 1",
                (name,),
            ).fetchone()
        return dict(row) if row else None


def _pack(values: Sequence[float]) -> bytes:
    import array

    return array.array("f", [float(v) for v in values]).tobytes()


def _unpack(blob: bytes, dim: int) -> tuple[float, ...]:
    import array

    data = array.array("f")
    data.frombytes(blob)
    if dim and len(data) != dim:
        return tuple(data[:dim])
    return tuple(data)


def pool_paths(entries: Iterable[SkillEntry]) -> list[str]:
    return [str(entry.path) for entry in entries]
