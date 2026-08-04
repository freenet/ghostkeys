#!/bin/bash
# Write delegate-key.json into the built webapp bundle, so apps can discover
# the current delegate instead of hardcoding it.
#
# WHY THIS EXISTS
#
# The delegate key is BLAKE3(BLAKE3(wasm) || params), so it changes whenever
# the delegate changes -- including for a bare version bump, which alters the
# WASM without altering behaviour. Users' stored keys migrate forward
# automatically (the vault sweeps `legacy_delegates.toml` on load), but an
# APP's reference to the delegate does not migrate: it is a build-time
# constant, and after a re-key it addresses a namespace that is now empty.
#
# On 2026-08-03 the delegate was re-keyed twice in one day. Every third-party
# integration broke, silently, and the first anyone knew of it was a user
# reporting that their Ghost Key "works in the vault but says no key found"
# elsewhere -- having been told to go and buy a key they already owned.
# See freenet/ghostkeys#21.
#
# So the delegate key is a public API. This publishes it as one.
#
# WHY IN THE WEBAPP BUNDLE, RATHER THAN A POINTER CONTRACT
#
# A separate contract holding the key would work, but it would need its own
# WASM, its own audit, and its own never-change guarantee -- and apps would
# hardcode ITS id instead, which is the same problem one level up.
#
# The vault's webapp contract already has every property needed:
#
#   - Its id is stable. The web container WASM and parameters are fixed, so
#     publishing a new version updates state, not the key. That is why the
#     vault URL has never changed.
#   - It is signed. The web container contract validates the signature, so a
#     file inside the bundle carries the same authority as the vault UI.
#   - It is republished on exactly the occasions the delegate re-keys, because
#     `publish-ghostkeys` builds the delegate into the UI. The pointer cannot
#     drift from what it points at without someone actively breaking the task
#     graph.
#
# That last property is the important one: correct by construction beats
# correct by remembering.
#
# The gateway serves bundle files at /v1/contract/web/<id>/<path>, with
# `Access-Control-Allow-Origin: *`, and a sandboxed app's CSP permits
# `connect-src <gateway origin>`. Verified 2026-08-04 from inside a sandboxed
# (opaque-origin) frame: fetch returns 200.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROFILE="${BUILD_PROFILE:-release}"
WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"
BUNDLE="target/dx/ghostkey-ui/${PROFILE}/web/public"
OUT="$BUNDLE/delegate-key.json"

if [ ! -f "$WASM" ]; then
    echo "ERROR: delegate WASM not found at $WASM" >&2
    echo "Run 'cargo make build-delegate' first." >&2
    exit 1
fi

if [ ! -d "$BUNDLE" ]; then
    echo "ERROR: webapp bundle not found at $BUNDLE" >&2
    echo "Run 'cargo make build-ui' first." >&2
    exit 1
fi

# Derived from the WASM that is about to be published, never from a recorded
# value -- a pointer copied from somewhere else can be stale, and a stale
# pointer is worse than no pointer because apps will trust it.
CODE_HASH="$(b3sum --no-names "$WASM")"
DELEGATE_KEY="$(printf '%s' "$CODE_HASH" | xxd -r -p | b3sum --no-names)"

# Byte arrays as well as hex: integrations bake these in as `number[]`
# (FreePlace's Vite config reads exactly this shape), and asking every
# integrator to write their own hex decoder invites an off-by-one nobody
# notices until a user cannot sign.
hex_to_json_array() {
    printf '%s' "$1" | python3 -c "
import sys
print('[' + ','.join(str(b) for b in bytes.fromhex(sys.stdin.read().strip())) + ']')
"
}

KEY_BYTES="$(hex_to_json_array "$DELEGATE_KEY")"
CODE_BYTES="$(hex_to_json_array "$CODE_HASH")"
PUBLISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "$OUT" <<EOF
{
  "_comment": "Current ghostkeys delegate. Fetch this instead of hardcoding a delegate key -- see https://github.com/freenet/ghostkeys/issues/21. Published with the vault webapp, so it cannot drift from the delegate it describes.",
  "schema": 1,
  "delegate_key": "$DELEGATE_KEY",
  "code_hash": "$CODE_HASH",
  "delegate_key_bytes": $KEY_BYTES,
  "code_hash_bytes": $CODE_BYTES,
  "published": "$PUBLISHED"
}
EOF

# A malformed pointer would be worse than none: apps would parse garbage and
# address a delegate that does not exist. Fail the publish instead.
python3 -c "
import json
d = json.load(open('$OUT'))
assert d['schema'] == 1, 'schema'
assert len(d['delegate_key']) == 64, 'delegate_key length'
assert len(d['code_hash']) == 64, 'code_hash length'
assert len(d['delegate_key_bytes']) == 32, 'key bytes length'
assert len(d['code_hash_bytes']) == 32, 'code hash bytes length'
assert bytes(d['delegate_key_bytes']).hex() == d['delegate_key'], 'key bytes vs hex'
assert bytes(d['code_hash_bytes']).hex() == d['code_hash'], 'code bytes vs hex'
" || { echo 'ERROR: generated delegate-key.json failed self-check' >&2; exit 1; }

echo "Wrote $OUT"
echo "  delegate_key = $DELEGATE_KEY"
echo "  code_hash    = $CODE_HASH"
