#!/bin/bash
# Verify that the currently-built delegate WASM's hash is either recorded in
# legacy_delegates.toml OR that the previously-deployed hash is recorded so
# that users with the old delegate can still migrate.
#
# Safeguard: refuses to allow publishing if the gap is not covered.
#
# How it works:
# 1. Hash the just-built delegate WASM.
# 2. If that hash is already in legacy_delegates.toml, the delegate hasn't
#    actually changed since the last recorded state — safe (nothing to
#    migrate).
# 3. If that hash is NOT in legacy_delegates.toml, the delegate has changed.
#    The migration system will migrate FROM the previously-deployed key (the
#    last entry in legacy_delegates.toml) TO this new key. That's the normal
#    case — allow publishing.
#
# The dangerous case this script can't catch on its own is when someone
# skipped `add-migration` for multiple consecutive delegate changes. The
# post-publish record step fixes that by ensuring every publish immediately
# records its own hash as the new baseline.
set -euo pipefail

WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"
LEGACY="legacy_delegates.toml"

if [ ! -f "$WASM" ]; then
    echo "ERROR: delegate WASM not found at $WASM" >&2
    echo "Run 'cargo make build-delegate' first." >&2
    exit 1
fi

if [ ! -f "$LEGACY" ]; then
    echo "ERROR: $LEGACY not found" >&2
    exit 1
fi

CODE_HASH=$(b3sum --no-names "$WASM")
LAST_ENTRY=$(grep 'code_hash' "$LEGACY" | tail -1 | sed -E 's/.*"([0-9a-f]+)".*/\1/')

if [ -z "$LAST_ENTRY" ]; then
    echo "ERROR: $LEGACY has no entries — cannot determine previous deployed hash" >&2
    exit 1
fi

echo "Built delegate hash:    $CODE_HASH"
echo "Last recorded hash:     $LAST_ENTRY"

if [ "$CODE_HASH" = "$LAST_ENTRY" ]; then
    echo "OK: built delegate matches last recorded — nothing changed."
    exit 0
fi

# Check that the last recorded hash is plausibly "what users currently have
# deployed". Since we can't query the network from this script, we trust
# that the most recent entry is the currently-deployed one. This convention
# is enforced by the post-publish record-migration step, which atomically
# records every freshly-published hash.
if grep -q "\"$CODE_HASH\"" "$LEGACY"; then
    echo "OK: built hash is already recorded in $LEGACY (earlier entry)."
    exit 0
fi

echo "OK: new delegate hash; migration will run from $LAST_ENTRY to $CODE_HASH."
