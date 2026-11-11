"""Violin router plugin: semantic skill routing and CVE lookup."""

from __future__ import annotations

from .builder import BuildReport, build_index, collect_pool, index_status
from .catalog import SkillEntry, SkillSource, collect_entries, pool_digest
from .cve import CveEntry, lookup as cve_lookup
from .dispatch import DispatchItem, DispatchQueue
from .embedding import Embedding, EmbeddingError, build_embedder, cosine
from .index import SearchHit, SkillIndex
from .scanner import ScanResult, scan_tool_result
from .triggers import Trigger, load_triggers, scan_text

__all__ = [
    "BuildReport",
    "CveEntry",
    "DispatchItem",
    "DispatchQueue",
    "Embedding",
    "EmbeddingError",
    "ScanResult",
    "SearchHit",
    "SkillEntry",
    "SkillIndex",
    "SkillSource",
    "Trigger",
    "build_embedder",
    "build_index",
    "collect_entries",
    "collect_pool",
    "cosine",
    "cve_lookup",
    "index_status",
    "load_triggers",
    "pool_digest",
    "scan_text",
    "scan_tool_result",
]
