#!/usr/bin/env python3
"""Snapshot a target's objective catalogue into the engagement state.

Targets that expose a record of their own objectives (labs, CTF platforms,
challenge applications) drive the objective-catalogue mode:
`skills/pentest/references/objective-catalogue.md`. This tool snapshots the
catalogue and writes a working summary of the open entries; re-run it before
and after every working batch — the target's own state is the only verdict.

The catalogue shape is detected, not assumed: a collection of records each
carrying a name, a description and an explicit state field (solved / done /
completed / captured, or a status string). The route name is whatever the
target uses; pass it with --url.

Usage (from the engagement root, via violin_exec):

    python3 scripts/sync-objectives.py --url http://TARGET/api/... \
        --out state/objectives.json --summary evidence/flags/objectives-status.json
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import urllib.error
import urllib.request

STATE_KEYS = ("solved", "done", "completed", "captured", "achieved")
NAME_KEYS = ("name", "title", "objective", "id")
DESC_KEYS = ("description", "desc", "detail", "summary")
DIFF_KEYS = ("difficulty", "level", "stars")
IDENT_KEYS = ("key", "id", "name", "slug")

AGENT = "Mozilla/5.0 (authorized-assessment; security-researcher@example.com)"


def fetch(url: str, timeout: float = 20.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _record_state(record: dict) -> bool | None:
    for key in STATE_KEYS:
        value = record.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in {"solved", "done", "closed", "complete", "completed"}:
            return True
        if isinstance(value, str) and value.strip().lower() in {"open", "unsolved", "pending"}:
            return False
    return None


def _first(record: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, (int, float)):
            return str(value)
    return ""


def detect_catalogue(data: object) -> list[dict] | None:
    """Return the catalogue records when *data* carries the objective shape."""
    records: object = data
    if isinstance(records, dict):
        for key in ("data", "objectives", "challenges", "items", "results"):
            if isinstance(records.get(key), list):
                records = records[key]
                break
        else:
            return None
    if not isinstance(records, list) or len(records) < 2:
        return None
    sample = [r for r in records if isinstance(r, dict)][:12]
    if len(sample) < 2:
        return None
    with_state = sum(1 for r in sample if _record_state(r) is not None)
    with_name = sum(1 for r in sample if _first(r, NAME_KEYS))
    with_desc = sum(1 for r in sample if _first(r, DESC_KEYS))
    # A catalogue: nearly every record carries a state and a name, and most a
    # description. Two records sharing a state polarity is not enough — the
    # point is a list the target maintains per objective.
    if with_state >= max(2, len(sample) - 1) and with_name >= len(sample) - 1 and with_desc >= len(sample) // 2:
        return [r for r in records if isinstance(r, dict)]
    return None


def summarise(records: list[dict]) -> dict:
    entries = []
    solved = 0
    for record in records:
        state = _record_state(record)
        if state is None:
            continue
        solved += 1 if state else 0
        if state:
            continue
        entries.append(
            {
                "id": _first(record, IDENT_KEYS),
                "name": _first(record, NAME_KEYS),
                "category": _first(record, ("category", "type", "tag")),
                "difficulty": _first(record, DIFF_KEYS),
                "description": _first(record, DESC_KEYS)[:600],
                "disabled_env": _first(record, ("disabledEnv", "disabled_env", "disabled")),
                "raw_state": {k: record[k] for k in STATE_KEYS if k in record},
            }
        )
    return {
        "synced_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "total": len(records),
        "solved": solved,
        "open": len(entries),
        "unsolved": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True, help="catalogue endpoint on the target")
    parser.add_argument("--out", default="state/objectives.json", help="snapshot path (engagement-relative)")
    parser.add_argument("--summary", default="evidence/flags/objectives-status.json", help="open-entry summary path")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    try:
        raw = fetch(args.url, args.timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"sync-objectives: fetch failed: {exc}", file=sys.stderr)
        return 2
    try:
        data = json.loads(raw.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("sync-objectives: response is not JSON", file=sys.stderr)
        return 2
    records = detect_catalogue(data)
    if records is None:
        print("sync-objectives: response does not match the objective-catalogue shape", file=sys.stderr)
        return 2

    import pathlib

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1))
    summary = summarise(records)
    summary_path = pathlib.Path(args.summary)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=1))
    print(
        f"objectives: {summary['solved']}/{summary['total']} closed, "
        f"{summary['open']} open — snapshot: {out}, open queue: {summary_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
