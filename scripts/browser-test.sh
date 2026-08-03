#!/bin/bash
# Build the vault UI and drive it in a real browser.
#
# Why this exists: the vault ships as a WASM bundle, so a Rust test that renders
# a component tree to a string does not exercise the compiled bundle, its event
# handlers, or its asset paths. Everything about whether a user can actually see
# and click the thing lives on the other side of that boundary.
#
# Runs with `--features example-data,no-sync`: no node connection, deterministic
# identities, and both the backed-up and un-backed-up states present.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PORT="${VAULT_TEST_PORT:-8977}"
echo "==> Building UI (example-data, no-sync)"
(cd ui && dx build --features example-data,no-sync >/dev/null)

BUNDLE="target/dx/ghostkey-ui/debug/web/public"
[ -f "$BUNDLE/index.html" ] || { echo "ERROR: no bundle at $BUNDLE" >&2; exit 1; }

# The gateway serves a webapp under /v1/contract/web/<id>/, and dx bakes that
# prefix into the bundle's asset URLs. Serving at `/` gives 404s for every asset
# and a blank page, so the harness reproduces the gateway's shape.
CONTRACT_PATH="$(grep -oE '/v1/contract/web/[A-Za-z0-9]+' "$BUNDLE/index.html" | head -1)"
if [ -z "$CONTRACT_PATH" ]; then
    echo "ERROR: could not find the contract path baked into index.html" >&2
    echo "The bundle layout changed; update this script and the spec." >&2
    exit 1
fi

SERVE_ROOT="$(mktemp -d)"
mkdir -p "$SERVE_ROOT$CONTRACT_PATH"
cp -r "$BUNDLE"/* "$SERVE_ROOT$CONTRACT_PATH/"

SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$SERVE_ROOT"
}
trap cleanup EXIT

echo "==> Serving $CONTRACT_PATH on :$PORT"
(cd "$SERVE_ROOT" && exec python3 -m http.server "$PORT" >/dev/null 2>&1) &
SERVER_PID=$!

URL="http://127.0.0.1:$PORT$CONTRACT_PATH/"
for _ in $(seq 1 30); do
    if curl -sf -o /dev/null "$URL"; then break; fi
    sleep 0.5
done
curl -sf -o /dev/null "$URL" || { echo "ERROR: server never came up at $URL" >&2; exit 1; }

echo "==> Running browser checks"
cd ui/tests/browser
[ -d node_modules ] || npm install --silent
VAULT_URL="$URL" node vault.spec.mjs
