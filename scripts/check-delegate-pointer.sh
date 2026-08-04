#!/bin/bash
# Verify the published pointer names the delegate that is actually shipping.
#
# The whole value of delegate-key.json is that apps can trust it. A pointer
# that disagrees with the bundled delegate is worse than none: integrators
# would address a delegate that does not exist and get exactly the silent
# failure this mechanism exists to prevent (freenet/ghostkeys#21).
#
# Runs as part of publish, after the archive is built and before it is signed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"
ARCHIVE="target/webapp/webapp.tar.xz"

for f in "$WASM" "$ARCHIVE"; do
    [ -f "$f" ] || { echo "ERROR: $f not found; run 'cargo make compress-webapp' first" >&2; exit 1; }
done

# What is actually about to be published.
ACTUAL_CODE_HASH="$(b3sum --no-names "$WASM")"
ACTUAL_KEY="$(printf '%s' "$ACTUAL_CODE_HASH" | xxd -r -p | b3sum --no-names)"

# What the archive tells apps.
if ! POINTER="$(tar -xJOf "$ARCHIVE" delegate-key.json 2>/dev/null)"; then
    echo "ERROR: delegate-key.json is missing from $ARCHIVE." >&2
    echo "Apps rely on it to find the current delegate. Is write-delegate-pointer" >&2
    echo "still wired into the compress-webapp task?" >&2
    exit 1
fi

CLAIMED_KEY="$(printf '%s' "$POINTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['delegate_key'])")"
CLAIMED_CODE_HASH="$(printf '%s' "$POINTER" | python3 -c "import json,sys; print(json.load(sys.stdin)['code_hash'])")"

FAILED=0
if [ "$CLAIMED_KEY" != "$ACTUAL_KEY" ]; then
    echo "ERROR: pointer names delegate_key $CLAIMED_KEY" >&2
    echo "       but the bundled delegate is  $ACTUAL_KEY" >&2
    FAILED=1
fi
if [ "$CLAIMED_CODE_HASH" != "$ACTUAL_CODE_HASH" ]; then
    echo "ERROR: pointer names code_hash $CLAIMED_CODE_HASH" >&2
    echo "       but the bundled delegate is $ACTUAL_CODE_HASH" >&2
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    echo "" >&2
    echo "Publishing this would hand integrators a key that resolves to nothing." >&2
    exit 1
fi

echo "OK: delegate-key.json matches the bundled delegate ($ACTUAL_KEY)."
