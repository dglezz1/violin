---
name: spec-driven-method
description: Test any API that publishes an OpenAPI/Swagger spec (or one you can render from its bundle): fetch the spec, build the endpoint matrix, map each operation to a guard class, probe by batch. Use when the target exposes /openapi.json, /swagger, /v2/api-docs, or an API-heavy surface; avoid when the target is a pure SPA with no API surface documented or discoverable.
version: 1.0.0
author: Violin
license: MIT
platforms: [linux, macos]
tags: [api, openapi, swagger, enumeration, coverage]
---

# Spec-driven API testing

The target's own specification is the enumeration: it names the operations,
the parameters and the auth requirements without touching a single endpoint.

## Method

1. **Find the spec** from the target itself: common locations
   (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/v2/api-docs`,
   `/api-docs`, `/swagger/v1/swagger.json`), the frontend bundle (search for
   `openapi`, `swagger`, `api-docs`), or a rendered docs page (`/swagger-ui`,
   `/docs`, `/api/docs`). If the target ships its spec in its repository and
   you have it locally, that is a legitimate target source too.
2. **Build the endpoint matrix**: for every operation, one row in
   `state/coverage-matrix.yaml` — method, path, parameters, auth requirement
   (from the spec's `security`/`securitySchemes`), and the response contract.
   This is the coverage queue.
3. **Map each operation to a guard class** by its semantics: auth endpoints →
   `authentication`/`jwt`; object-by-id operations → `idor`;
   write operations with wide bodies → `mass-assignment`; search/filter →
   `sqli`; file/URL parameters → `path-traversal`/`ssrf`; admin operations →
   `broken-access-control`.
4. **Auth first**: register/login per the spec's own auth flow, capture the
   token, and note which operations the spec marks as protected.
5. **Probe by batch** (`violin_exec_burst`): for each class, a batch of
   operations × payloads. Re-derive expectations from the spec's declared
   responses — a 200 where the spec promises 401 is a signal; a 500 where it
   promises 4xx is another.
6. **Close the matrix**: every operation ends `tested` (with evidence) or
   `not_applicable` (with the probe file), per
   `skills/pentest/references/exhaustive-coverage.md`.

## With ZAP

For breadth, run the mechanical pipeline and verify its leads through the
guard (`scripts/zap-pipeline.py` in the profile): ZAP spiders and scans, the
pipeline maps alerts to guard classes into `evidence/zap/alerts.jsonl`, and
each alert is a lead — verified, never submitted as-is.
