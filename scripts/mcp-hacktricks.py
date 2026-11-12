#!/usr/bin/env python3
"""MCP server: the HackTricks methodology library, as consultable tools.

Exposes the whole HackTricks catalogue (hacktricks.wiki) to the agent as an
L1/L2 resource: search over the index of articles, fetch the full article on
demand. Nothing is fetched at startup beyond the index; article bodies are
cached on disk with a TTL, so repeated consultations cost nothing and work
offline once seen.

Runs over MCP stdio (JSON-RPC, newline-delimited) with the standard library
only — no SDK, no network at import time.

Register in the profile's config.yaml:

    mcp_servers:
      hacktricks:
        command: <venv python>
        args: [<this file>]
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from pathlib import Path

REPO_RAW = "https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/{path}"
REPO_TREE = "https://api.github.com/repos/HackTricks-wiki/hacktricks/git/trees/master?recursive=1"
INDEX_TTL = 7 * 24 * 3600.0
ARTICLE_TTL = 7 * 24 * 3600.0

_HOME = Path.home() / ".hermes" / "violin-router" / "hacktricks"
_INDEX = _HOME / "index.json"
_ARTICLES = _HOME / "articles"

TOOLS = [
    {
        "name": "hacktricks_search",
        "description": (
            "Search the HackTricks methodology library (pentesting web/network/"
            "cloud/mobile/binary/AI, ~2000 articles) by topic. Returns the best "
            "matching article paths and titles; load the article with "
            "hacktricks_get."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Technique or topic (e.g. '403 bypass', 'JWT attacks', 'redis pentest')"},
                "limit": {"type": "integer", "description": "Max results (default 8)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "hacktricks_get",
        "description": (
            "Fetch one HackTricks article in full (markdown). Cached on disk "
            "after the first fetch, so re-reads are instant and offline."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Article path as returned by hacktricks_search (repo-relative .md path)"},
            },
            "required": ["path"],
        },
    },
]


def _load_index(force: bool = False) -> list[dict]:
    """The article index: path + title, from the repo tree, cached a week."""
    if not force and _INDEX.is_file():
        try:
            data = json.loads(_INDEX.read_text())
            if time.time() - data.get("at", 0) < INDEX_TTL:
                return data.get("articles") or []
        except (json.JSONDecodeError, OSError):
            pass
    request = urllib.request.Request(REPO_TREE, headers={"User-Agent": "violin-mcp"})
    with urllib.request.urlopen(request, timeout=60) as response:
        tree = json.loads(response.read().decode())
    articles = []
    for entry in tree.get("tree") or []:
        path = entry.get("path") or ""
        if not path.endswith(".md") or "/images/" in path:
            continue
        title = path.rsplit("/", 1)[-1][: -len(".md")].replace("-", " ").replace("_", " ")
        articles.append({"path": path, "title": title})
    _HOME.mkdir(parents=True, exist_ok=True)
    _INDEX.write_text(json.dumps({"at": time.time(), "articles": articles}))
    return articles


def _terms(query: str) -> list[str]:
    return [w for w in re.split(r"[^a-z0-9]+", (query or "").lower()) if len(w) > 2]


def search(query: str, limit: int = 8) -> list[dict]:
    """Rank articles by term overlap on path + title (BM25-lite, no fetch)."""
    terms = _terms(query)
    if not terms:
        return []
    scored = []
    for article in _load_index():
        hay = f"{article['path'].lower()} {article['title'].lower()}"
        matched = sum(1 for t in terms if t in hay)
        if not matched:
            continue
        score = matched / len(terms) + (0.3 if any(t in article["title"].lower() for t in terms) else 0.0)
        scored.append((score, article))
    scored.sort(key=lambda item: -item[0])
    return [
        {"path": article["path"], "title": article["title"], "score": round(score, 3)}
        for score, article in scored[: max(1, limit)]
    ]


def get_article(path: str) -> str:
    """One article in full markdown, cached on disk with a TTL."""
    if not path.endswith(".md") or ".." in path or path.startswith("/"):
        raise ValueError("path must be a repo-relative .md path")
    _ARTICLES.mkdir(parents=True, exist_ok=True)
    cache = _ARTICLES / (path.replace("/", "__")[:180] or "index.md")
    if cache.is_file() and time.time() - cache.stat().st_mtime < ARTICLE_TTL:
        return cache.read_text(encoding="utf-8", errors="replace")
    request = urllib.request.Request(REPO_RAW.format(path=path), headers={"User-Agent": "violin-mcp"})
    with urllib.request.urlopen(request, timeout=45) as response:
        body = response.read().decode("utf-8", errors="replace")
    cache.write_text(body, encoding="utf-8")
    return body


def _call(name: str, arguments: dict) -> dict:
    if name == "hacktricks_search":
        results = search(str(arguments.get("query") or ""), int(arguments.get("limit") or 8))
        text = (
            "\n".join(f"- {r['title']}  →  {r['path']}  (score {r['score']})" for r in results)
            or "no matching article — try the technique's canonical name"
        )
        return {"content": [{"type": "text", "text": text}]}
    if name == "hacktricks_get":
        body = get_article(str(arguments.get("path") or ""))
        return {"content": [{"type": "text", "text": body[:120000]}]}
    raise ValueError(f"unknown tool: {name}")


def _respond(request: dict, result: dict | None, error: dict | None = None) -> str:
    message: dict = {"jsonrpc": "2.0", "id": request.get("id")}
    if error:
        message["error"] = error
    else:
        message["result"] = result
    return json.dumps(message)


def serve() -> int:
    """MCP stdio loop: newline-delimited JSON-RPC, standard library only."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = request.get("method") or ""
        if method == "initialize":
            sys.stdout.write(_respond(request, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "hacktricks", "version": "1.0.0"},
            }) + "\n")
        elif method == "tools/list":
            sys.stdout.write(_respond(request, {"tools": TOOLS}) + "\n")
        elif method == "tools/call":
            params = request.get("params") or {}
            try:
                result = _call(str(params.get("name") or ""), params.get("arguments") or {})
                sys.stdout.write(_respond(request, result) + "\n")
            except Exception as exc:
                sys.stdout.write(_respond(request, None, {
                    "code": -32000, "message": f"hacktricks: {exc}",
                }) + "\n")
        elif method == "ping":
            sys.stdout.write(_respond(request, {}) + "\n")
        elif request.get("id") is not None:
            sys.stdout.write(_respond(request, {}) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
