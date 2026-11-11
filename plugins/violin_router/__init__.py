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
from pathlib import Path
from typing import Any

from .core import (
    DispatchQueue,
    build_index,
    cve_lookup,
    index_status,
    scan_tool_result,
)
from .core.binding import bound_classes, check_binding
from .core.objectives import detect_catalogue, dispatch_note as objective_dispatch_note

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


def _handle_router_classes(raw: Any = None, **kwargs: Any) -> str:
    """List the vulnerability classes that can be tested, and how.

    The guard decides which classes are routable; this surfaces that list so
    the coverage standard ("every class, against every route") is reachable
    without the agent having to guess which classes exist. For each class it
    names the guard's canonical skill and the pool playbooks that cover it.

    Args:
        eng_dir: Engagement directory (unused, kept for signature parity).
    """
    from .core.surface import guard_vocabulary, resolve

    classes = guard_vocabulary()
    rows = []
    for name in classes:
        refs = resolve(vulnerability_class=name)
        rows.append(
            {
                "class": name,
                "skills": [ref.name for ref in refs],
            }
        )
    return json.dumps(
        {
            "count": len(rows),
            "classes": rows,
            "note": (
                "every class here can be recorded as a hypothesis (vuln_class) and "
                "tested; a class you did not test is a gap in the coverage matrix"
            ),
        },
        ensure_ascii=False,
    )


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
    command = ""
    phase = ""
    if isinstance(args, dict):
        command = str(args.get("command") or args.get("cmd") or "")
        phase = str(args.get("phase") or "")
        # Any tool argument that names a path inside the engagement registers
        # it — eng_dir for guard tools, cwd for executors, path/file_path for
        # the file tools — so engagement-level notes flow from the first turn,
        # before the first guard call.
        session = str(kwargs.get("session_id") or "")
        for value in args.values():
            if isinstance(value, str) and value.startswith("/"):
                _register_engagement(Path(value).expanduser(), session)
    try:
        scan_tool_result(
            str(tool_name),
            result,
            exec_ref=str(kwargs.get("tool_call_id") or ""),
            session_id=str(kwargs.get("session_id") or ""),
            command=command,
        )
    except Exception:
        # The router is advisory: a scan failure must never block the agent.
        return
    if phase:
        _remember_phase(phase)
    _maybe_queue_objective_mode(tool_name, result, args, kwargs)


_LAST_PHASE: list[str] = []


_OBJECTIVE_NOTE_INTERVAL = 45 * 60  # re-dispatch after long sessions / compaction


def _maybe_queue_objective_mode(
    tool_name: Any, result: Any, args: Any, kwargs: Any
) -> None:
    """Queue the objective-mode note when a target response looks like a catalogue.

    The detection is on the response shape, not on a route name, so any target
    that publishes its own objective record arms the mode without the operator
    asking for it. The note lives in the engagement, so it survives gateway
    restarts, and re-arms after an interval so a long session re-receives it
    after its context was compacted.
    """
    text = result if isinstance(result, str) else str(result or "")
    if not text:
        return
    try:
        session = str(kwargs.get("session_id") or "")
        # Executor results carry the working directory: the cold-start source
        # of the session-to-engagement association, before any guard call
        # names the engagement.
        if text.lstrip().startswith("{") and '"cwd"' in text[:600]:
            try:
                payload = json.loads(text[: text.rfind("}") + 1])
                cwd = payload.get("cwd")
                if isinstance(cwd, str) and cwd:
                    _register_engagement(Path(cwd).expanduser(), session)
            except (json.JSONDecodeError, ValueError):
                pass
        if detect_catalogue(text) is None:
            return
        dirs = _engagement_dirs()
        if not dirs:
            return
        import time as _time

        note_path = dirs[0] / "state" / "objective-mode.note"
        if note_path.is_file() and (_time.time() - note_path.stat().st_mtime) < _OBJECTIVE_NOTE_INTERVAL:
            return
        note_path.parent.mkdir(parents=True, exist_ok=True)
        note_path.write_text(objective_dispatch_note(), encoding="utf-8")
    except Exception:
        # Advisory layer: never break the agent's turn over a detection.
        return


def _remember_phase(phase: str) -> None:
    """Remember the phase the agent is working in.

    The ``pre_llm_call`` hook does not carry the phase and a terminal call
    does not either, so the phase is read from the engagement's own PTT: the
    active task is the guard's record of what the agent is doing.
    """
    value = phase.strip().upper()
    if value:
        _LAST_PHASE[:] = [value]
        return
    _LAST_PHASE[:] = [_active_task_phase()]


def _active_task_phase() -> str:
    """The phase of the engagement's active PTT task, if it can be read."""
    for candidate in _engagement_dirs():
        ptt_path = candidate / "state" / "ptt.md"
        if not ptt_path.is_file():
            continue
        try:
            text = ptt_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        phase = ""
        for line in text.splitlines():
            heading = line.strip()
            if heading.startswith("## Phase:"):
                phase = heading.split("## Phase:", 1)[1].strip().upper()
            elif heading.startswith("## ") and phase:
                phase = ""
            if line.startswith("|") and "[~]" in line and phase:
                # The legend at the top of the file also carries a "[~]" cell;
                # a task row is one that starts with a task id.
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                if cells and cells[0].startswith("PT-"):
                    return phase
        if phase:
            return phase
    return ""


_ENGAGEMENT_DIRS: list[Path] = []


def _engagement_registry_path() -> Path:
    from .core.index import default_index_dir

    return default_index_dir() / "engagements.jsonl"


def _register_engagement(path: Path, session_id: str = "") -> None:
    """Register *path*, or its nearest engagement ancestor, as the session's.

    An engagement is a directory holding the guard's canonical scope and PTT;
    a tool that runs in a subdirectory of one (evidence/, ops/, ...) still
    belongs to it.
    """
    try:
        candidates = [path, *path.parents]
    except OSError:
        return
    for candidate in candidates:
        if candidate in _ENGAGEMENT_DIRS:
            return
        if (candidate / "scope" / "scope.yaml").is_file() and (
            candidate / "state" / "ptt.md"
        ).is_file():
            _ENGAGEMENT_DIRS.insert(0, candidate)
            if session_id:
                _remember_session_engagement(session_id, candidate)
            return


def _remember_session_engagement(session_id: str, path: Path) -> None:
    """Persist the session-to-engagement association across hook calls.

    The gateway process holds every profile session, and its working
    directory is not the engagement's, so the association is the only thing
    that lets a pre_llm_call hook find the engagement it is talking about.
    """
    import time as _time

    try:
        registry = _engagement_registry_path()
        registry.parent.mkdir(parents=True, exist_ok=True)
        with registry.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"session_id": session_id, "eng_dir": str(path), "at": _time.time()}
                )
                + "\n"
            )
    except OSError:
        pass


def _session_engagement(session_id: str) -> Path | None:
    """The most recent engagement a session was seen working in."""
    if not session_id:
        return None
    try:
        registry = _engagement_registry_path()
        if not registry.is_file():
            return None
        best: tuple[float, Path] | None = None
        for line in registry.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("session_id") != session_id:
                continue
            path = Path(str(row.get("eng_dir") or ""))
            at = float(row.get("at") or 0)
            if path.is_dir() and (best is None or at > best[0]):
                best = (at, path)
        return best[1] if best else None
    except OSError:
        return None


def _engagement_dirs() -> list[Path]:
    """The engagement directories this session may be working in.

    A directory qualifies as an engagement when it holds a scope and a PTT;
    the search starts at the environment override, then the process working
    directory and its parents, so a session that starts inside an engagement
    finds it without being told where it is.
    """
    if _ENGAGEMENT_DIRS:
        return _ENGAGEMENT_DIRS
    candidates: list[Path] = []
    override = os.environ.get("VIOLIN_ENG_DIR", "").strip()
    if override:
        candidates.append(Path(override).expanduser())
    try:
        cwd = Path.cwd().resolve()
        candidates.append(cwd)
        candidates.extend(cwd.parents)
    except OSError:
        pass
    for candidate in candidates:
        if (candidate / "scope" / "scope.yaml").is_file() and (
            candidate / "state" / "ptt.md"
        ).is_file():
            _register_engagement(candidate)
            break
    return _ENGAGEMENT_DIRS


def _drain_objective_note(session_id: str = "") -> list[str]:
    """Deliver a queued objective-mode note once, then remove it."""
    out: list[str] = []
    dirs = list(_engagement_dirs())
    by_session = _session_engagement(session_id)
    if by_session is not None and by_session not in dirs:
        dirs.insert(0, by_session)
    for candidate in dirs:
        note_path = candidate / "state" / "objective-mode.note"
        try:
            if not note_path.is_file():
                continue
            text = note_path.read_text(encoding="utf-8", errors="replace").strip()
            if text:
                out.append(text)
            note_path.unlink()
        except OSError:
            continue
    return out


def _vocabulary_note(phase: str) -> str:
    """The routable class vocabulary, surfaced once per phase.

    The coverage standard is "every class, against every route". The agent
    cannot cover a class it does not know exists, and the guard's routing
    table is what decides. Surfacing it removes the guess without telling the
    agent what is vulnerable.

    It is repeated rather than sent once: a long engagement compacts its
    context, and a note that was compacted away would leave the later part of
    the engagement working from a shorter list than the earlier part.
    """
    key = phase.strip().upper()
    if not key:
        # No phase was observed yet in this session: read it from the
        # engagement's own PTT, which is the guard's record of the active task.
        key = _active_task_phase()
    if not key or key in {"SCOPING", "RECON"}:
        return ""
    from .core.surface import guard_vocabulary, parallel_hint

    classes = guard_vocabulary()
    if not classes:
        return ""
    groups: dict[str, list[str]] = {}
    for name in classes:
        groups.setdefault(name.split("-")[0], []).append(name)
    summary = "; ".join(
        f"{group}: {', '.join(sorted(names))}" for group, names in sorted(groups.items())
    )
    hint = parallel_hint(list(classes))
    note = (
        "\n[SKILL DISPATCH] vocabulary de clases — clases que el gate puede enrutar "
        f"({len(classes)}):\n{summary}\n"
        "Cobertura exhaustiva = cada clase contra cada ruta. Registra cada clase no "
        "probada como hipótesis con vuln_class, o ciérrala con evidencia."
    )
    if hint:
        note += f"\n[PARALELISMO] {hint}"
    note += (
        "\n[ESTADO] El engagement ya tiene estado: lee state/coverage-matrix.yaml "
        "(rutas ya probadas), hypotheses.md (hipótesis abiertas y clases ya "
        "descartadas) y state/history.md (comandos ya ejecutados) ANTES de "
        "reconocer o re-probar. Reexplorar lo ya cubierto no aporta cobertura; "
        "las rutas no cubiertas y las clases sin hipótesis son el trabajo "
        "pendiente."
    )
    note += (
        "\n[LOTE] Sondea por lotes, no de una en una. Una llamada con "
        "tool_call(tool_name=\"violin_exec_burst\", arguments={...\"commands\":[...], "
        "\"target\":..., \"phase\":...}) ejecuta hasta 20 comandos en UN turno y deja "
        "un receipt firmado por comando. Veinte sondas cuestan un turno; una por "
        "turno cuesta veinte. Agrupa por clase: todas las sondas de una clase en "
        "un lote, luego el siguiente lote."
    )
    return note


_HANDOFF_DELIVERED: set[str] = set()


def _session_handoff(eng_dir: Path) -> str:
    """A one-turn handoff for a session resuming an engagement with state.

    A resumed session must not re-run the discovery a previous session paid
    for. This summarises what the engagement already knows — objectives
    closed, what is still open, classes already refuted — in a few hundred
    tokens, and it is delivered once per session. The state stays on disk in
    the engagement; nothing from another scope ever enters this one.
    """
    key = str(eng_dir)
    if key in _HANDOFF_DELIVERED:
        return ""
    _HANDOFF_DELIVERED.add(key)
    parts: list[str] = []

    objectives = eng_dir / "state" / "objectives.json"
    if objectives.is_file():
        try:
            data = json.loads(objectives.read_text(encoding="utf-8")).get("data") or []
            solved = [c for c in data if c.get("solved")]
            open_items = [
                c for c in data if not c.get("solved")
            ]
            open_items.sort(key=lambda c: (c.get("difficulty") or 9))
            parts.append(
                f"[HANDOFF] objetivo tracker del target: {len(solved)}/{len(data)} cerrados; "
                f"{len(open_items)} abiertos (los 5 más baratos: "
                + "; ".join(f"{c['name']} (d={c.get('difficulty')})" for c in open_items[:5])
                + "). La lista completa vive en state/objectives.json; no re-probes lo cerrado."
            )
        except (json.JSONDecodeError, OSError):
            pass

    hyp = eng_dir / "hypotheses.md"
    if hyp.is_file():
        try:
            text = hyp.read_text(encoding="utf-8", errors="replace")
            rejected = []
            for block in text.split("### ")[1:]:
                title = block.splitlines()[0][:60]
                if "Status:** Rejected" in block and "Vuln Class:**" in block:
                    cls = block.split("Vuln Class:**", 1)[1].splitlines()[0].strip()
                    rejected.append(f"{cls} ({title})")
            if rejected:
                parts.append(
                    "[HANDOFF] clases ya refutadas con evidencia — no repitas estos tests: "
                    + "; ".join(rejected[:8])
                )
        except OSError:
            pass

    matrix = eng_dir / "state" / "coverage-matrix.yaml"
    if matrix.is_file():
        try:
            tested = sum(
                1 for line in matrix.read_text(encoding="utf-8", errors="replace").splitlines()
                if "status: tested" in line
            )
            if tested:
                parts.append(
                    f"[HANDOFF] coverage matrix: {tested} rutas ya enumeradas y probadas "
                    f"(state/coverage-matrix.yaml); las rutas sin celda son el trabajo pendiente."
                )
        except OSError:
            pass

    # Mechanical resources the session can spend its budget on, named only
    # when they exist: ZAP leads already mapped to classes, and the headless
    # renderer for objectives whose trigger lives in the rendered app.
    zap = eng_dir / "evidence" / "zap" / "alerts.jsonl"
    if zap.is_file():
        try:
            leads = sum(1 for line in zap.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
            if leads:
                parts.append(
                    f"[HANDOFF] {leads} leads mecánicos de ZAP en evidence/zap/alerts.jsonl "
                    "(cada uno con su clase ya mapeada): verifícalos por el guard antes de "
                    "enviarlos — un lead no es un finding."
                )
        except OSError:
            pass
    parts.append(
        "[HANDOFF] objetivos que nombren páginas/UI/sinks de DOM: rendirlos con "
        "Chromium headless del perfil (sh ops/headless-dom.sh <url> <name> — DOM, "
        "screenshot y texto a evidence/client/); el API no muestra lo que el "
        "render monta. Skill: client-side-render."
    )

    return "\n\n".join(parts)


def _transform_tool_result_hook(
    tool_name: Any = None,
    args: Any = None,
    result: Any = None,
    **kwargs: Any,
) -> str | None:
    """Deliver a queued engagement note by appending it to a tool result.

    ``pre_llm_call`` does not run in non-interactive one-shot sessions, but
    this hook does, and its return value is what enters the context — so the
    objective-mode note reaches the agent through the same path in both
    interactive and one-shot runs. One delivery per arming: the note is
    consumed when it is appended.
    """
    if result is None:
        return None
    try:
        session = str(kwargs.get("session_id") or "")
        if not session:
            # Register from the same signals the scanner uses, so a cold
            # start finds the engagement even before the first guard call.
            if isinstance(args, dict):
                for value in args.values():
                    if isinstance(value, str) and value.startswith("/"):
                        _register_engagement(Path(value).expanduser(), session or "")
            text_now = result if isinstance(result, str) else str(result)
            if text_now.lstrip().startswith("{") and '"cwd"' in text_now[:600]:
                try:
                    payload = json.loads(text_now[: text_now.rfind("}") + 1])
                    cwd = payload.get("cwd")
                    if isinstance(cwd, str) and cwd:
                        _register_engagement(Path(cwd).expanduser(), session)
                except (json.JSONDecodeError, ValueError):
                    pass
        delivered: list[str] = []
        for candidate in ([_session_engagement(session)] if session else []) + list(
            _engagement_dirs()
        ):
            if candidate is None:
                continue
            handoff = _session_handoff(candidate)
            if handoff:
                delivered.append(handoff)
            note_path = candidate / "state" / "objective-mode.note"
            try:
                if not note_path.is_file():
                    continue
                note = note_path.read_text(encoding="utf-8", errors="replace").strip()
                if not note:
                    continue
                note_path.unlink()
            except OSError:
                continue
            delivered.append(note)
            break
        if delivered:
            base = result if isinstance(result, str) else str(result)
            return f"{base}\n\n" + "\n\n".join(delivered)
    except Exception:
        return None
    return None


def _pre_llm_call_hook(session_id: Any = None, eng_dir: Any = None, **kwargs: Any) -> str:
    """Inject the pending dispatch notes into the model's turn."""
    try:
        parts: list[str] = []
        pending = [item for item in DispatchQueue().load() if not item.delivered]
        for item in pending[:4]:
            parts.append(item.note())
            DispatchQueue().mark_delivered(item)
        parts.extend(_drain_objective_note(str(kwargs.get("session_id") or "")))
        note = _vocabulary_note(str(kwargs.get("phase") or (_LAST_PHASE[0] if _LAST_PHASE else "")))
        if note:
            parts.append(note)
        return "\n\n".join(parts)
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
        name="violin_router_classes",
        toolset=_TOOLSET,
        schema={
            "name": "violin_router_classes",
            "description": (
                "List every vulnerability class that can be tested in this engagement, "
                "with the playbooks that cover it. Call it before planning so the "
                "coverage standard is reachable without guessing which classes exist."
            ),
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
        handler=_handle_router_classes,
        emoji="🧭",
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
    ctx.register_hook("transform_tool_result", _transform_tool_result_hook)
    ctx.register_hook("pre_llm_call", _pre_llm_call_hook)


__all__ = ["register"]
