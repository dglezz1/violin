#!/bin/sh
# Render a page the way a browser does and persist the rendered state.
#
# Some objectives only trigger in the rendered application, never in a raw
# HTTP response. This drives the profile's own agent-browser (the same
# runtime the browser toolset uses), through violin_exec so the run keeps its
# receipt, and leaves the snapshot tree, a screenshot and the page text under
# evidence/client/.
#
# Usage (from the engagement root, via violin_exec):
#   sh ops/headless-dom.sh "http://localhost:3000/#/score-board" [out-name]
set -u

URL="${1:?usage: headless-dom.sh <url> [out-name]}"
NAME="${2:-page-$(date +%s)}"
OUT="evidence/client"
mkdir -p "$OUT"

AB="${AGENT_BROWSER:-$HOME/.hermes/tools/agent-browser-0.26.0-darwin-arm64/bin/agent-browser-darwin-arm64}"
if [ ! -x "$AB" ]; then
  AB="$(command -v agent-browser 2>/dev/null || true)"
fi
if [ -z "$AB" ] || [ ! -x "$AB" ]; then
  echo "headless-dom: agent-browser binary not found (set AGENT_BROWSER)"
  exit 2
fi

"$AB" open "$URL" > "$OUT/$NAME.open" 2>&1
sleep 4
"$AB" snapshot > "$OUT/$NAME.snapshot" 2>&1

# Most targets greet the first visit with a consent dialog that hides the
# page; dismiss it from the snapshot's own refs and re-render, so the
# snapshot shows the application and not the greeting.
if grep -q "cookieconsent\|consent" "$OUT/$NAME.snapshot" 2>/dev/null; then
  REF=$(grep -oE 'button "[^"]*" \[ref=([a-z0-9]+)\]' "$OUT/$NAME.snapshot" \
    | grep -iE "dismiss|accept|want|consent|agree|ok" \
    | grep -oE "ref=[a-z0-9]+" | head -1 | cut -d= -f2)
  if [ -n "$REF" ]; then
    "$AB" click "$REF" > /dev/null 2>&1
    sleep 2
    "$AB" snapshot > "$OUT/$NAME.snapshot" 2>&1
  fi
fi

"$AB" screenshot "$OUT/$NAME.png" > /dev/null 2>&1
"$AB" close > /dev/null 2>&1

SNAP="$OUT/$NAME.snapshot"
if [ ! -s "$SNAP" ]; then
  echo "headless-dom: render failed — see $OUT/$NAME.open"
  exit 1
fi

echo "snapshot: $SNAP | screenshot: $OUT/$NAME.png"
echo "════ rendered tree (first 60 lines) ════"
head -60 "$SNAP"
