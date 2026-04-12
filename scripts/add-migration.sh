#!/bin/bash
# Record the current delegate WASM's key in legacy_delegates.toml.
# Run this BEFORE making changes to delegates/ or common/ that alter the WASM.
set -euo pipefail

WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"

if [ ! -f "$WASM" ]; then
    echo "Delegate WASM not found. Building..."
    cargo build --target wasm32-unknown-unknown --release -p ghostkey-delegate
fi

CODE_HASH=$(b3sum --no-names "$WASM")
DELEGATE_KEY=$(echo -n "$CODE_HASH" | xxd -r -p | b3sum --no-names)

# Check if already recorded
if grep -q "$DELEGATE_KEY" legacy_delegates.toml 2>/dev/null; then
    echo "Delegate key already in legacy_delegates.toml"
    exit 0
fi

echo "" >> legacy_delegates.toml
echo "# Added $(date +%Y-%m-%d)" >> legacy_delegates.toml
echo "[[entry]]" >> legacy_delegates.toml
echo "code_hash = \"$CODE_HASH\"" >> legacy_delegates.toml
echo "delegate_key = \"$DELEGATE_KEY\"" >> legacy_delegates.toml

echo "Added migration entry:"
echo "  code_hash = $CODE_HASH"
echo "  delegate_key = $DELEGATE_KEY"
