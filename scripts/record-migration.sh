#!/bin/bash
# Append the just-published delegate WASM's hash to legacy_delegates.toml if
# not already present, and commit the change.
#
# Called automatically by `cargo make publish-ghostkeys` after a successful
# publish, so every deployed hash is recorded as the new baseline and the
# next delegate change can migrate from it without anyone having to
# remember to run `add-migration` first.
set -euo pipefail

WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"

if [ ! -f "$WASM" ]; then
    echo "ERROR: delegate WASM not found at $WASM" >&2
    exit 1
fi

CODE_HASH=$(b3sum --no-names "$WASM")
DELEGATE_KEY=$(echo -n "$CODE_HASH" | xxd -r -p | b3sum --no-names)

if grep -q "\"$CODE_HASH\"" legacy_delegates.toml 2>/dev/null; then
    echo "Deployed delegate hash already recorded in legacy_delegates.toml."
    exit 0
fi

echo "" >> legacy_delegates.toml
echo "# Added $(date +%Y-%m-%d) (post-publish)" >> legacy_delegates.toml
echo "[[entry]]" >> legacy_delegates.toml
echo "code_hash = \"$CODE_HASH\"" >> legacy_delegates.toml
echo "delegate_key = \"$DELEGATE_KEY\"" >> legacy_delegates.toml

echo "Recorded published delegate hash in legacy_delegates.toml:"
echo "  code_hash    = $CODE_HASH"
echo "  delegate_key = $DELEGATE_KEY"
echo ""
echo "Remember to commit and push legacy_delegates.toml so the next"
echo "delegate change can migrate from this deployed state."
