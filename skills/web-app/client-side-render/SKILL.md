---
name: client-side-render
description: Reach objectives that only trigger in the rendered application — SPA routes, DOM sinks, state that exists after JavaScript ran. Drives the profile's own Chromium headless through violin_exec and persists DOM + screenshot as evidence. Use when a target objective names a page, a section, a UI element, or a DOM property; avoid when the objective is reachable by a plain API request.
version: 1.0.0
author: Violin
license: MIT
platforms: [macos, linux]
tags: [client-side, dom, spa, browser, xss, rendering]
---

# Client-side render (headless)

The API shows what the server says; the browser shows what the application
actually does. Objectives that name a page, a UI section, a DOM property or a
client-side sink live on the rendered side.

## Method

1. **Enumerate the client routes** from the target's own bundle: the SPA's
   route table (grep the bundle for route literals) or the router config it
   ships. Write every route into `state/coverage-matrix.yaml` like any other
   route.
2. **Render, don't guess**: for each route that an objective names,

   ```sh
   sh ops/headless-dom.sh "http://localhost:3000/#/<route>" <route-name>
   ```

   (the script ships with the profile; copy it to `ops/` once). It runs the
   profile's Chromium headless through `violin_exec`, and leaves the rendered
   DOM, a screenshot and the page text under `evidence/client/` — evidence
   with a receipt, not a claim.
3. **Read the rendered text** in the script's output: the objective's target
   (a page that appeared, a widget that loaded, a sink that fired) is visible
   in the text where the raw API response showed nothing.
4. **Interact where rendering is not enough**: DOM XSS and client-side state
   need a payload rendered through the same path. Inject via the route's own
   parameter (query, fragment, stored field), re-render, and diff the DOM
   against the clean render — the diff is the proof.
5. **Close the objective** the standard way: hypothesis with the client-side
   class, re-sync the tracker, the objective's state on the target is the
   only verdict.

## When not to

If the objective is satisfiable by an API request, the API path is cheaper
and produces cleaner evidence. Rendering is for what the API cannot show.
