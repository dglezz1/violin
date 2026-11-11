#!/usr/bin/env python3
"""Fan the engagement out to one Violin agent per vulnerability family.

One agent per engagement is the guard's concurrency model, so parallelism is
expressed as one SUB-engagement per family: each gets its own PTT, sync
credits and receipts, and its own agent working only the objectives whose
trigger maps to its classes. The target's own objective tracker is the shared
source of truth — every family re-syncs it, and the union of closed
objectives is the campaign's coverage. Nothing is shared but the target.

Usage:

    python3 scripts/orchestrate-families.py --template /path/to/engagement \\
        --out /path/to/campaign-root --agents 4 --timeout 7200

The template must hold a validated, authorised scope.yaml. Each child gets a
copy of it, a full guard bootstrap (ctf mode), and the mechanical per-family
prompt; no vulnerability is named in the prompt — the families come from the
guard's own class vocabulary.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# The guard's routing vocabulary, collapsed into families an agent can own.
FAMILIES: dict[str, tuple[str, ...]] = {
    "injection": (
        "sqli", "sql-injection", "nosql-injection", "ldap-injection",
        "xpath-injection", "xss", "cross-site-scripting", "ssti",
        "command-injection", "xxe", "deserialization", "prototype-pollution",
        "prompt-injection", "llm-prompt-injection",
    ),
    "auth-session": (
        "auth", "authn", "authz", "authentication", "authorization",
        "auth-bypass", "missing-authentication", "default-credentials",
        "jwt", "jwt-attacks", "cryptographic-issues", "csrf",
        "security-through-obscurity",
    ),
    "access-logic": (
        "idor", "idor-access-control", "broken-access-control",
        "broken-object-level-authorization", "access-control",
        "mass-assignment", "business-logic", "logic-flaw",
        "workflow-state-abuse", "cors", "open-redirect",
        "redirects-unvalidated", "rate-limit", "rate-limiting",
    ),
    "infra-api": (
        "misconfiguration", "security-misconfiguration", "path-traversal",
        "ssrf", "server-side-request-forgery", "observability-failures",
        "graphql", "json-rpc", "websocket", "rest-api", "api-security",
        "input-validation", "mcp", "mcp-api-testing", "false-positive",
        "static-analysis", "source-analysis", "sarif", "codebase", "domain",
        "osint", "public-records", "repository", "supply-chain", "username",
        "identity", "semgrep", "codeql",
    ),
}

FAMILY_PROMPT = """Authorized engagement — you own the vulnerability families: {families}.

ENG_DIR = {eng_dir}
TARGET: http://localhost:3000 (authorized, deliberately vulnerable lab).

The target exposes its own record of objectives with their live state. That
record is your work queue and its state on the target is the only verdict;
your first tool result carries the full method ([OBJECTIVE MODE]). Work it
with ONE restriction: you handle ONLY objectives whose trigger maps to your
families ({families}). Other families are other agents' work — skip their
objectives without probing them. The class of an objective comes from its own
description mapped onto the guard's vocabulary (`violin_router_classes`).

Method per objective: hypothesis (vuln_class from YOUR families) → playbook
(violin_skill_search + violin_skill_view) → PTT bind → violin_exec probe (or
violin_exec_burst) → re-sync the tracker (`sh ops/sync_objectives.sh`) — the
tracker on the target is the only verdict. Captured values go to
state/flag-register.md. Blocked after ~5 approaches: record the blocker, move
on. Rate: at most 5 req/s, sequential. No destructive operations. Never
search online for the trigger.

Tools: guard tools via tool_call(tool_name=..., arguments={{...}}) with
eng_dir={eng_dir}; router tools direct. Guard tools are deferred.
"""


def _bootstrap(eng: Path, venv_python: Path) -> None:
    result = subprocess.run(
        [str(venv_python), "-c",
         "import sys; sys.path.insert(0, '%s'); "
         "from plugins.violin_guard.core.engagement import bootstrap; "
         "bootstrap.init_engagement(sys.argv[1], host='localhost', ctf=True)" % (
             (Path(__file__).resolve().parent.parent).as_posix()
         ),
         str(eng)],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"bootstrap failed for {eng}: {result.stderr[-400:]}")


def make_sub_engagement(template: Path, out: Path, name: str, venv_python: Path) -> Path:
    eng = out / name
    if eng.exists():
        shutil.rmtree(eng)
    eng.mkdir(parents=True)
    for item in ("scope", "ops"):
        src = template / item
        if src.is_dir():
            shutil.copytree(src, eng / item)
    _bootstrap(eng, venv_python)
    return eng


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--agents", type=int, default=4, choices=range(1, len(FAMILIES) + 1))
    parser.add_argument("--timeout", type=int, default=7200)
    parser.add_argument("--hermes", default="hermes")
    parser.add_argument("--profile", default="violin")
    parser.add_argument("--venv-python",
                        default=str(Path.home() / ".hermes/profiles/violin/.venv/bin/python"))
    args = parser.parse_args()

    template = Path(args.template).expanduser().resolve()
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not (template / "scope" / "scope.yaml").is_file():
        print("orchestrate: template needs a validated scope.yaml", file=sys.stderr)
        return 2

    selected = list(FAMILIES.items())[: args.agents]
    procs = []
    for name, classes in selected:
        try:
            eng = make_sub_engagement(template, out, f"family-{name}", Path(args.venv_python))
        except (RuntimeError, subprocess.SubprocessError) as exc:
            print(f"orchestrate: skipping {name}: {exc}", file=sys.stderr)
            continue
        prompt = FAMILY_PROMPT.format(families=", ".join(classes), eng_dir=str(eng))
        (eng / "PROMPT.md").write_text(prompt)
        log = open(out / f"{name}.log", "w")
        env = dict(os.environ)
        env["ENG_DIR"] = str(eng)
        proc = subprocess.Popen(
            [args.hermes, "-p", args.profile, "--in", str(eng), "-z", prompt],
            stdout=log, stderr=subprocess.STDOUT, cwd=str(eng), env=env,
            # Decouple from the launcher's process group: the harness (or any
            # wrapper) tearing down its own tree must not take the family
            # agents with it.
            start_new_session=True,
        )
        procs.append((name, proc))
        print(f"launched {name} -> {eng} (pid {proc.pid})", flush=True)
        time.sleep(2.0)

    (out / "campaign.json").write_text(json.dumps(
        {"launched_at": time.time(),
         "families": [{"family": n, "eng_dir": str(Path(args.out) / f"family-{n}"),
                       "classes": list(c)} for n, c in selected]},
        indent=1))

    print(f"{len(procs)} family agents running; campaign root: {out}", flush=True)
    deadline = time.time() + args.timeout

    # Waves: an agent that exits cleanly has done what it saw; the
    # engagement's own state brings the next wave up to date (handoff), so a
    # relaunch continues the queue instead of repeating it. Waves run until
    # the campaign budget is spent.
    wave = 1
    while time.time() < deadline and procs:
        next_wave = []
        for family, proc in procs:
            remaining = max(60.0, deadline - time.time())
            try:
                code = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                print(f"{family}: still running at the budget", flush=True)
                continue
            print(f"{family}: exit {code}", flush=True)
            if code == 0 and time.time() < deadline - 300:
                eng = out / f"family-{family}"
                prompt = (eng / "PROMPT.md").read_text()
                log = open(out / f"{family}.wave{wave + 1}.log", "w")
                env = dict(os.environ)
                env["ENG_DIR"] = str(eng)
                proc = subprocess.Popen(
                    [args.hermes, "-p", args.profile, "--in", str(eng), "-z", prompt],
                    stdout=log, stderr=subprocess.STDOUT, cwd=str(eng), env=env,
                    start_new_session=True,
                )
                print(f"{family}: wave {wave + 1} launched (pid {proc.pid})", flush=True)
                next_wave.append((family, proc))
        procs = next_wave
        wave += 1

    print("campaign complete — the union of closed objectives across the "
          "trackers is the coverage", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
