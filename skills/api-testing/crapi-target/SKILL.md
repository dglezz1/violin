---
name: crapi-target
description: Target kit for OWASP crAPI (completely ridiculous API) — where its official OpenAPI spec lives, how to map its service layout into the endpoint matrix, and which deployment ports its services use. Use when the assessed target is crAPI; avoid for any other target.
version: 1.0.0
author: Violin
license: MIT
platforms: [linux, macos]
tags: [crapi, owasp, api, target-kit, openapi]
---

# crAPI target kit

OWASP crAPI is an intentionally vulnerable API training application. This kit
is mechanical: it points at the target's own published material so the
enumeration starts from the target, not from a writeup.

## Local resources (shipped with this profile)

- `references/target-specs/crapi-openapi.json` — the official OpenAPI spec
  (40 paths / 65 operations), fetched from the OWASP/crAPI repository. Use it
  to build the endpoint matrix offline, and re-fetch it from the live target
  (`/openapi.json` style routes) if it serves one.

## Surface map (from the spec, not from lore)

The spec groups operations by service: identity (auth, tokens, user),
community (posts, comments), workshop (vehicles, invoices, feedback), admin
(diagnostic, users). Map each group through the spec-driven method:

- identity operations drive the authentication/JWT matrix;
- object-by-id reads and writes across services drive the
  broken-access-control matrix;
- wide request bodies drive the mass-assignment matrix;
- search/filter and location parameters drive the injection matrix.

Follow `../spec-driven-method/SKILL.md` for the loop, and
`../references/target-specs/crapi-openapi.json` for the operations. Deployment
layout (docker-compose ports, mail service for reset flows) is in the same
repository the spec came from.
