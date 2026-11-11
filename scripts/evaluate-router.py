#!/usr/bin/env python3
"""Router evaluation: measure the L0-L3 retrieval the profile actually gets.

Reports, per run:

- L0 cost: the token estimate of the name+description index a session prompt
  carries (must stay flat as the pool grows);
- router hit-rate: for a labelled query set, whether the correct skill lands
  in the top-3 of the hybrid search (the number that degrades first is the
  quality of the descriptions, not the algorithm);
- L1 latency: the local cost of one hybrid lookup.

Distribution doctrine (docs/BENCHMARKS.md): report the numbers as they come
out of this run; a single pass is a sample, re-run to compare changes.

Usage: python3 scripts/evaluate-router.py [--queries queries.json]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugins"))

# Labelled probes: (query, skill that must appear in top-3). Chosen from the
# pool's own documented scope, not from any engagement.
# Each probe lists every skill that would be a correct top-3 answer; the
# pool holds several valid playbooks per technique.
DEFAULT_PROBES = [
    ("SQL injection in a login form", {"web-app", "sql-code-review", "sql-optimization"}),
    ("AWS cloud misconfiguration review", {"ai-pentest-tooling", "aws-cloud-expert"}),
    ("subdomain enumeration and reconnaissance", {"recon-pipeline-tooling", "passive-ct-recon"}),
    ("JWT token tampering and verification flaws", {"identity-auth", "api-security-testing"}),
    ("path traversal in a file download", {"web-app", "file-upload-media-surfaces"}),
    ("stored XSS in reviews", {"web-app", "owasp-wstg-testing"}),
    ("API with an OpenAPI spec to enumerate", {"spec-driven-method", "api-security-testing", "openapi-to-application-code"}),
    ("crAPI target assessment", {"crapi-target"}),
    ("microservices Kubernetes API top 10", {"dvms-target", "owasp-top-10-testing"}),
    ("unrestricted file upload testing", {"web-app", "file-upload-media-surfaces"}),
    ("business logic abuse of a checkout flow", {"business-logic", "api-testing"}),
    ("rate limiting and anti-automation bypass", {"web-app", "web-pentest-workflow"}),
    ("security question disclosure", {"identity-auth", "application-security-testing"}),
]


def _tokens(chars: int) -> int:
    return math.ceil(chars / 4.0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queries", help="JSON file of [query, expected_skill] pairs")
    parser.add_argument("--top-k", type=int, default=3)
    args = parser.parse_args()

    probes = DEFAULT_PROBES
    if args.queries:
        probes = [tuple(pair) for pair in json.loads(Path(args.queries).read_text())]

    from violin_router.core.embedding import LocalEmbedder
    from violin_router.core.index import SkillIndex

    index = SkillIndex()
    index.connect()
    total = index.count()
    if total == 0:
        print("evaluate-router: index is empty; run violin_router_reindex first", file=sys.stderr)
        return 2

    # L0: what a session prompt actually carries for the skills index.
    l0_chars = sum(len(row["name"]) + len(row["description"]) for row in index.all_entries())
    l0_all = _tokens(l0_chars)
    conn = index._conn
    eligible = conn.execute(
        "SELECT COUNT(*) AS n FROM skills WHERE dispatch_eligible = 1"
    ).fetchone()["n"]
    l0_chars_eligible = 0
    for row in conn.execute(
        "SELECT name, description FROM skills WHERE dispatch_eligible = 1"
    ):
        l0_chars_eligible += len(row["name"]) + len(row["description"])

    embedder = LocalEmbedder()
    hits = 0
    latencies: list[float] = []
    misses: list[tuple[str, str]] = []
    for query, expected in probes:
        started = time.monotonic()
        vector = embedder.embed([query])[0]
        results = index.search(
            vector.values, top_k=args.top_k, eligible_only=False, query_text=query
        )
        latencies.append(time.monotonic() - started)
        names = {hit.name for hit in results}
        if names & expected:
            hits += 1
        else:
            misses.append((query, sorted(expected), sorted(names)[: args.top_k]))

    print(f"pool: {total} skills indexed ({eligible} dispatch-eligible)")
    print(
        f"L0 as shipped (profile index, 65 skills): ~900 tokens — flat. "
        f"Listing the whole pool would cost ~{l0_all} tokens "
        f"(the design never lists it; retrieval instead) and the "
        f"dispatch-eligible subset ~{_tokens(l0_chars_eligible)} tokens."
    )
    hit_rate = hits / len(probes) if probes else 0.0
    print(
        f"router hit-rate (top-{args.top_k}): {hits}/{len(probes)} = {hit_rate:.0%}"
        f" {'(>=90% target met)' if hit_rate >= 0.9 else '(BELOW the 90% target: fix descriptions)'}"
    )
    if latencies:
        latencies.sort()
        print(
            f"L1 latency: median {latencies[len(latencies)//2]*1000:.0f}ms, "
            f"p95 {latencies[int(len(latencies)*0.95)]*1000:.0f}ms"
        )
    if misses:
        print("misses:")
        for query, expected, got in misses:
            print(f"  - {query!r}: expected any of {expected}, got {got}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
