"""Violin Router — semantic skill routing and CVE lookup for Violin.

The plugin watches target-facing output, detects vulnerability classes and
technology signals, and dispatches the matching playbooks mechanically: the
model is told which class was found and which skills to consult, and the
engine's own skill gate refuses to let the class be tested without a linked
skill. Nothing here reaches the target.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .core import (
    DispatchQueue,
    build_index,
    cve_lookup,
    index_status,
    scan_tool_result,
)
from .core.binding import bound_classes, check_binding

_TOOLSET = "violin_router"


def _args(raw: Any = None, **kwargs: Any) -> dict[str, Any]:
    """Normalise a tool payload.

    Hermes calls a plugin handler with the raw argument dictionary as a single
    positional argument; some surfaces pass keyword arguments instead. Both
    shapes are accepted so the tool behaves the same wherever it is invoked.
    """
    payload: dict[str, Any] = {}
    if isinstance(raw, dict):
        payload.update(raw)
    elif raw is not None:
        payload["query"] = raw
    payload.update({key: value for key, value in kwargs.items() if value is not None})
    return payload


def _handle_skill_search(raw: Any = None, **kwargs: Any) -> str:
    """Search the indexed playbook pool.

    Args:
        query: Free-text description of what you need (a technique, a class,
            a technology). The nearest playbooks are returned by name.
        top_k: How many results to return.
        eng_dir: Engagement directory (unused, kept for signature parity).
    """
    from .core.embedding import EmbeddingError, build_embedder
    from .core.index import SkillIndex

    payload = _args(raw, **kwargs)
    query = str(payload.get("query") or "")
    top_k = payload.get("top_k") or 5
    if not query.strip():
        return json.dumps({"error": "query must not be empty"})
    index = SkillIndex()
    index.connect()
    if index.count() == 0:
        index.close()
        return json.dumps(
            {
                "error": "skill index is empty",
                "hint": "run violin_router_reindex to build it",
            }
        )
    try:
        embedder = build_embedder(os.environ.get("VIOLIN_EMBED_PROVIDER", "auto"))
        vectors = embedder.embed([query])
    except EmbeddingError as exc:
        index.close()
        return json.dumps({"error": f"embedding backend unavailable: {exc}"})
    if not vectors:
        index.close()
        return json.dumps({"error": "embedding backend returned no vector"})
    hits = index.search(
        vectors[0].values,
        top_k=max(1, int(top_k)),
        eligible_only=False,
        query_text=query,
    )
    index.close()
    return json.dumps(
        {
            "query": query,
            "count": len(hits),
            "results": [hit.as_dict() for hit in hits],
            "usage": (
                "call violin_skill_view with one of the returned names to load its body; "
                "the body is delivered on demand and never preloaded into the prompt"
            ),
        },
        ensure_ascii=False,
    )


def _handle_skill_view(raw: Any = None, **kwargs: Any) -> str:
    """Load the body of an indexed playbook on demand.

    The body is read from the indexed path and returned as a tool result, so
    it enters the conversation without ever being part of the system prompt.

    Args:
        name: Skill name, as returned by violin_skill_search.
        vulnerability_class: The class being tested, when the guard routes
            the class to a bundled skill. Supplying it lets the router check
            the engagement's binding before releasing the playbook.
        eng_dir: Engagement directory.
    """
    from pathlib import Path

    from .core.index import SkillIndex

    payload = _args(raw, **kwargs)
    name = str(payload.get("name") or "")
    vulnerability_class = str(payload.get("vulnerability_class") or "")
    eng_dir = str(payload.get("eng_dir") or "")
    if not name.strip():
        return json.dumps({"error": "name must not be empty"})
    index = SkillIndex()
    index.connect()
    entry = index.find_by_name(name.strip())
    index.close()
    if entry is None:
        return json.dumps({"error": f"skill {name!r} is not in the index"})
    if vulnerability_class.strip():
        classes = bound_classes(Path(eng_dir)) if eng_dir else ()
        check = check_binding(
            vulnerability_class.strip(),
            str(entry.get("name") or name),
            ptt_bound_classes=classes,
        )
        if not check.allowed:
            return json.dumps(
                {
                    "error": "binding check failed",
                    "reason": check.reason,
                    "expected_skill": check.expected_skill,
                    "hint": (
                        "record the vulnerability class and its skill in the PTT "
                        "before testing it"
                    ),
                },
                ensure_ascii=False,
            )
    path = Path(str(entry.get("path") or ""))
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return json.dumps({"error": f"cannot read skill body: {exc}"})
    body = _strip_frontmatter(content)
    return json.dumps(
        {
            "name": entry.get("name"),
            "source": entry.get("source"),
            "category": entry.get("category"),
            "path": str(path),
            "content": body,
        },
        ensure_ascii=False,
    )


def _strip_frontmatter(text: str) -> str:
    """Drop the YAML frontmatter: the index already carries that metadata."""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            return parts[2].lstrip("\n")
    return text


def _handle_cve_lookup(raw: Any = None, **kwargs: Any) -> str:
    """Look up recent advisories for a technology or package.

    Args:
        technology: Technology keyword detected during testing (for example
            "express", "django", "log4j", "aws").
        version: Detected version, when known.
        package: Exact package name, when it differs from the technology.
        eng_dir: Engagement directory (unused, kept for signature parity).
    """
    payload = _args(raw, **kwargs)
    technology = str(payload.get("technology") or "")
    version = str(payload.get("version") or "")
    package = str(payload.get("package") or "")
    if not technology.strip() and not package.strip():
        return json.dumps({"error": "technology or package must not be empty"})
    result = cve_lookup(technology, version=version, package=package)
    return json.dumps(result, ensure_ascii=False)


def _handle_router_status(raw: Any = None, **kwargs: Any) -> str:
    """Report the state of the skill index and the dispatch queue.

    Args:
        eng_dir: Engagement directory (unused, kept for signature parity).
    """
    status = index_status()
    queue = DispatchQueue()
    items = queue.load()
    status["queue"] = {
        "path": str(queue.path),
        "items": len(items),
        "pending": len([i for i in items if not i.delivered]),
        "triggers": sorted({i.trigger for i in items}),
    }
    return json.dumps(status, ensure_ascii=False)


def _handle_router_reindex(raw: Any = None, **kwargs: Any) -> str:
    """Build or refresh the skill index.

    Args:
        force: Rebuild even when the skill pool has not changed.
        eng_dir: Engagement directory (unused, kept for signature parity).
    """
    payload = _args(raw, **kwargs)
    report = build_index(force=bool(payload.get("force")))
    return json.dumps(report.as_dict(), ensure_ascii=False)


def _post_tool_call_hook(
    tool_name: str | None = None,
    args: Any = None,
    result: Any = None,
    duration_ms: int = 0,
    **kwargs: Any,
) -> None:
    """Scan target-facing tool output for vulnerability and technology signals."""
    if not tool_name:
        return
    try:
        scan_tool_result(
            str(tool_name),
            result,
            exec_ref=str(kwargs.get("tool_call_id") or ""),
            session_id=str(kwargs.get("session_id") or ""),
        )
    except Exception:
        # The router is advisory: a scan failure must never block the agent.
        return


def _pre_llm_call_hook(session_id: Any = None, eng_dir: Any = None, **kwargs: Any) -> str:
    """Inject the pending dispatch notes into the model's turn."""
    try:
        queue = DispatchQueue()
        pending = [item for item in queue.load() if not item.delivered]
        if not pending:
            return ""
        notes = []
        for item in pending[:4]:
            notes.append(item.note())
            queue.mark_delivered(item)
        if not notes:
            return ""
        return "\n\n".join(notes)
    except Exception:
        return ""


def register(ctx: Any) -> None:
    """Called once by the plugin loader during discovery."""
    ctx.register_tool(
        name="violin_skill_search",
        toolset=_TOOLSET,
        schema={
            "name": "violin_skill_search",
            "description": (
                "Search the indexed playbook pool (Violin, Hermes security skills, "
                "Strix, Dark-Moon) by meaning. Returns skill names only; load a body "
                "with skill_view."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "What you need a playbook for.",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "How many results to return (default 5).",
                        "default": 5,
                    },
                    "eng_dir": {
                        "type": "string",
                        "description": "Engagement directory.",
                    },
                },
                "required": ["query"],
            },
        },
        handler=_handle_skill_search,
        emoji="🔎",
    )
    ctx.register_tool(
        name="violin_skill_view",
        toolset=_TOOLSET,
        schema={
            "name": "violin_skill_view",
            "description": (
                "Load the body of an indexed playbook. The body enters the "
                "conversation as a tool result and is never preloaded into the "
                "prompt. When the class is being tested, pass vulnerability_class "
                "so the engagement binding is checked first."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Skill name, as returned by violin_skill_search.",
                    },
                    "vulnerability_class": {
                        "type": "string",
                        "description": "The class being tested, when known.",
                    },
                    "eng_dir": {
                        "type": "string",
                        "description": "Engagement directory.",
                    },
                },
                "required": ["name"],
            },
        },
        handler=_handle_skill_view,
        emoji="📖",
    )
    ctx.register_tool(
        name="violin_cve_lookup",
        toolset=_TOOLSET,
        schema={
            "name": "violin_cve_lookup",
            "description": (
                "Look up recent advisories for a technology or package detected while "
                "testing, so a finding is checked against known CVEs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "technology": {
                        "type": "string",
                        "description": "Technology keyword (express, django, log4j, aws...).",
                    },
                    "version": {
                        "type": "string",
                        "description": "Detected version, when known.",
                    },
                    "package": {
                        "type": "string",
                        "description": "Exact package name, when it differs.",
                    },
                    "eng_dir": {
                        "type": "string",
                        "description": "Engagement directory.",
                    },
                },
            },
        },
        handler=_handle_cve_lookup,
        emoji="🗒️",
    )
    ctx.register_tool(
        name="violin_router_status",
        toolset=_TOOLSET,
        schema={
            "name": "violin_router_status",
            "description": "Report the skill index state and the pending dispatch queue.",
            "parameters": {
                "type": "object",
                "properties": {
                    "eng_dir": {
                        "type": "string",
                        "description": "Engagement directory.",
                    },
                },
            },
        },
        handler=_handle_router_status,
        emoji="📊",
    )
    ctx.register_tool(
        name="violin_router_reindex",
        toolset=_TOOLSET,
        schema={
            "name": "violin_router_reindex",
            "description": (
                "Build or refresh the skill index. Only needed when the skill pool "
                "changed; it is skipped automatically otherwise."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "force": {
                        "type": "boolean",
                        "description": "Rebuild even when the pool is unchanged.",
                        "default": False,
                    },
                    "eng_dir": {
                        "type": "string",
                        "description": "Engagement directory.",
                    },
                },
            },
        },
        handler=_handle_router_reindex,
        emoji="🔁",
    )
    ctx.register_hook("post_tool_call", _post_tool_call_hook)
    ctx.register_hook("pre_llm_call", _pre_llm_call_hook)


__all__ = ["register"]
