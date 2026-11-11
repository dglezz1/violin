---
name: dvms-target
description: Target kit for Damn Vulnerable MicroServices (ne0z/DVMS) — Kubernetes microservices built to exercise the OWASP API Security Top 10, with its service layout and repository resources. Use when the assessed target is DVMS; avoid for any other target.
version: 1.0.0
author: Violin
license: MIT
platforms: [linux]
tags: [dvms, microservices, kubernetes, target-kit]
---

# DVMS target kit

Damn Vulnerable MicroServices is a Kubernetes microservices application built
to exercise the OWASP API Security Top 10. Mechanical kit only: the target's
own repository is the permitted source.

## Local resources

- `references/target-specs/dvms-readme.md` — the project's own README
  (deployment model, disclaimer, scope of the exercise).

## Surface map

- Enumerate the services from the deployment itself: `kubectl get` views of
  services/ingress (the repo's `kubernetes-manifests/` mirror what a live
  deployment exposes) and port-forward or cluster-internal routes as the
  scope defines.
- Each service gets its own coverage rows; inter-service calls are in scope
  only as the rules of engagement allow.
- Apply `../spec-driven-method/SKILL.md` per service, and the
  microservice-specific angles the OWASP API Top 10 names: object-level
  authorization between tenants, excessive data exposure in service-to-service
  responses, and resource consumption without rate limiting.
