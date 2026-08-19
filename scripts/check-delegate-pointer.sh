#!/bin/bash
# Verify everything that names the delegate agrees with the delegate that is
# actually shipping.
#
# ghostkeys publishes the delegate's identity through TWO channels, and both
# are checked here against the same source of truth — the WASM about to be
# bundled:
#
#   1. delegate-key.json inside the signed webapp bundle (the original
#      stopgap, still supported; see scripts/write-delegate-pointer.sh).
#   2. The signed pointer record in pointer-records.toml, which is what
#      third parties resolve at a fixed address (see FREENET.md).
#
# The whole value of both is that apps can trust them. One that disagrees with
# the bundled delegate is worse than none: integrators would address a delegate
# that does not exist and get exactly the silent failure this mechanism exists
# to prevent (freenet/ghostkeys#21).
#
# Channel 2 needs its own check HERE, and not only in CI, because the two ask
# different questions. check-pointer-freshness asks whether the record names
# what this SOURCE builds, on every PR. This asks whether it names what is
# about to be PUBLISHED, which is the only moment the two can be made to
# coincide — a record can be perfectly fresh against a source tree that is not
# what gets published, and nothing else would notice.
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

TOML_PATH="pointer-records.toml"
[ -f "$TOML_PATH" ] || { echo "ERROR: $TOML_PATH not found" >&2; exit 1; }

# Hard requirement, not a soft skip. A missing tool here would silently drop
# the pointer half of this gate on exactly the machine doing the publishing,
# which is the one place it has to run.
command -v pointer-record >/dev/null 2>&1 || {
    echo "ERROR: pointer-record not found. Install with:" >&2
    echo "  cargo install --git https://github.com/freenet/freenet-migrate \\" >&2
    echo "    --rev 5e1759c39f98ec54f51c84d632e28fc33578b48d --features publish --locked freenet-pointer-contract" >&2
    exit 1
}

# The same reader the freshness gate, the signer and the publish script use.
# All four must agree about what a record says.
. "$(dirname "${BASH_SOURCE[0]}")/pointer-toml-lib.sh"

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

# ------------------------------------------------- channel 2: the pointer record
APP_ID="ghostkeys.ghostkey-delegate"
AUTHOR_VK="$(pointer_top_field "$TOML_PATH" author_verifying_key)"
REC_I="$(pointer_index_of_app "$TOML_PATH" "$APP_ID")"

if [ -z "$AUTHOR_VK" ]; then
    echo "ERROR: no author_verifying_key in $TOML_PATH" >&2
    FAILED=1
elif [ -z "$REC_I" ]; then
    # Not a soft warning. The pointer address is live on the network whether or
    # not this file still describes it, so a publish with no record here ships a
    # delegate the published pointer does not name.
    echo "ERROR: $TOML_PATH has no [[record]] for $APP_ID." >&2
    echo "       The pointer address stays live and would keep answering with the" >&2
    echo "       PREVIOUS delegate. Run scripts/sign-pointer-records.sh." >&2
    FAILED=1
else
    REC_HASH="$(pointer_field "$TOML_PATH" "$REC_I" code_hash)"
    REC_VERSION="$(pointer_field "$TOML_PATH" "$REC_I" version)"
    REC_STATE="$(pointer_field "$TOML_PATH" "$REC_I" state)"
    REC_KEY="$(pointer_field "$TOML_PATH" "$REC_I" pointer_key)"

    if [ "$REC_HASH" != "$ACTUAL_CODE_HASH" ]; then
        echo "ERROR: $TOML_PATH names code_hash $REC_HASH" >&2
        echo "       but the delegate being published is $ACTUAL_CODE_HASH" >&2
        echo "       Run scripts/sign-pointer-records.sh and commit the result." >&2
        FAILED=1
    elif ! pointer-record verify --author-vk "$AUTHOR_VK" --app-id "$APP_ID" \
            --state "$REC_STATE" --expect-version "$REC_VERSION" \
            --expect-code-hash "$REC_HASH" --expect-key "$REC_KEY" >/dev/null; then
        # The hash comparison above is two strings in files we control, so on
        # its own it accepts a hand-edited hash that left its signature behind.
        echo "ERROR: the pointer record for $APP_ID does not verify." >&2
        echo "       Do not hand-edit the record; run scripts/sign-pointer-records.sh." >&2
        FAILED=1
    fi
fi

if [ "$FAILED" -ne 0 ]; then
    echo "" >&2
    echo "Publishing this would hand integrators a key that resolves to nothing." >&2
    exit 1
fi

echo "OK: delegate-key.json matches the bundled delegate ($ACTUAL_KEY)."
echo "OK: pointer record $APP_ID v$REC_VERSION names it too ($REC_KEY)."
echo ""
echo "Reminder: signing is not publishing. The pointer record goes to the network"
echo "separately, from main after merge: scripts/publish-pointer-records.sh"
