# Skill Router — semantic playbook routing and CVE lookup

`violin_router` is a second Violin plugin. It widens the set of playbooks the
agent can reach without touching the execution boundary the guard owns.

## What it does

**Indexes a local skill pool.** Violin, the Hermes security skills, Strix and
Dark-Moon playbooks are indexed as a vector index (`skills.vecdb`). Only the
frontmatter and a short excerpt of each playbook are embedded; the body stays
on disk and is delivered on demand. The index never enters a prompt.

**Detects classes in target output.** Every result of a target-facing command
(`violin_exec`, `violin_exec_burst`) is scanned in two levels:

1. a deterministic regex trigger table (`assets/triggers.yaml`) — cheap, exact,
   auditable;
2. an embedding fallback, only when the table finds nothing — this catches the
   vocabulary a fixed table cannot enumerate (a WAF banner, a framework-specific
   error).

Both levels write into one dispatch queue. A detection records its origin
(`regex` or `embedding`), its score and the skills it maps to, so a semantic
hit is as traceable as a literal one.

**Dispatches mechanically.** The pending notes are injected into the model's
turn through the `pre_llm_call` hook. The model is told which class was
detected and which playbooks to consult; the enforcement stays the guard's —
a class cannot be tested without a linked skill.

**Looks up recent advisories.** `violin_cve_lookup` queries OSV for the
technology a finding touches, so a finding is checked against known CVEs.

## Tools

| Tool | Purpose |
|---|---|
| `violin_skill_search` | Semantic search over the playbook pool. Returns names only. |
| `violin_skill_view` | Loads one playbook body on demand, as a tool result. |
| `violin_cve_lookup` | Recent advisories (OSV) for a technology or package. |
| `violin_router_status` | Index state and pending dispatch queue. |
| `violin_router_reindex` | Rebuilds the index; skipped when the pool is unchanged. |

## Where its state lives

The index and the dispatch queue live in a sidecar directory outside the
distributed plugin tree, so a profile update never destroys them:

```
~/.hermes/violin-router/skills.vecdb
~/.hermes/violin-router/dispatch_queue.jsonl
```

`VIOLIN_ROUTER_HOME` overrides the location.

The index carries a digest of the embedded text, so it is rebuilt only when the
skill pool actually changes — not per engagement.

## Embeddings

The default backend is a local ONNX model (`bge-small-en-v1.5`), so no
target-derived text leaves the host. A remote OpenRouter-compatible endpoint
is available and is used only when the local runtime is unavailable:

```
VIOLIN_EMBED_PROVIDER=auto|local|remote
```

The remote backend is also the path to use a different model (for example
`nvidia/llama-nemotron-embed-vl-1b-v2:free`). It has two limits worth
knowing: the endpoint caps a request at roughly 8K tokens in total, and the
free tier answers 504 while its worker cold-starts, so the client retries.

## Relationship to the guard

The router is additive. It never relaxes the guard's policy: it asks the
guard's own routing module which skill a vulnerability class maps to, and it
checks the engagement's binding before releasing a playbook for that class.
The guard remains the component that refuses.

## What the dispatch carries

The note injected into the agent's turn is what makes the router effective. It
carries:

- **the class that was detected**, with the playbooks that cover it, resolved
  from the class and from the surface the command touched;
- **the routable class vocabulary**, read from the guard's own routing table,
  so the coverage standard ("every class, against every route") is reachable
  without the agent having to guess which classes exist;
- **where the engagement's state is**, so a resumed session continues from the
  coverage matrix and the hypothesis board instead of re-enumerating what a
  previous turn already covered;
- **the batch command** (`violin_exec_burst` takes up to 20 commands in one
  turn), which is how a class gets tested in a turn rather than twenty;
- **the independent class families**, which can be tested in parallel.

None of it names a vulnerability in the target. It tells the agent what the
method is and where the state is; what is actually exploitable is what the
agent has to find.

## Loopback labs

A loopback address is refused as a primary target by default — that is the
shape an SSRF or a mis-pointed scope takes. A deliberately local lab opts in
explicitly, in the scope that names it:

```yaml
rules_of_engagement:
  allow_loopback_primary_target: true
```

Without that flag the refusal stands, and an excluded host stays excluded
either way.
