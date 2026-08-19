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

# The expected revision, read from the CI gate so there is ONE place to bump it.
# `|| true` because `set -o pipefail` is active: a missing line makes grep exit
# 1, which would kill the script SILENTLY here -- before the explicit emptiness
# check below could say what was wrong. Absorb the status, then handle the empty
# value deliberately. (Absorbing WITHOUT then handling it is the fail-open trap
# that the record-count guard in the other scripts exists to close.)
POINTER_TOOL_REV="$(grep -m1 '^POINTER_TOOL_REV=' \
    "$(dirname "${BASH_SOURCE[0]}")/check-pointer-freshness.sh" \
    | sed 's/.*:-\([0-9a-f]*\)}.*/\1/' || true)"
[ -n "$POINTER_TOOL_REV" ] || {
    echo "ERROR: could not read POINTER_TOOL_REV from check-pointer-freshness.sh" >&2
    exit 1
}

# Hard requirement, not a soft skip. A missing tool here would silently drop
# the pointer half of this gate on exactly the machine doing the publishing,
# which is the one place it has to run.
command -v pointer-record >/dev/null 2>&1 || {
    echo "ERROR: pointer-record not found. Install with:" >&2
    echo "  cargo install --git https://github.com/freenet/freenet-migrate \\" >&2
    echo "    --rev $POINTER_TOOL_REV --features publish --locked freenet-pointer-contract" >&2
    exit 1
}

# And it must be the PINNED revision, not whatever is on PATH.
#
# CI verifies with a rev-pinned build; without this the publishing machine
# verified with anything at all, so the two could disagree about what a valid
# record IS and only the looser one would be consulted at the moment it counts.
# check-pointer-freshness.sh states the rule this applies: "a gate whose oracle
# can change under it is not a gate." It was stated there and not applied here.
#
# A KNOWN mismatch is fatal. An UNKNOWN version only warns, because
# `cargo install --list` cannot see a binary installed by other means, and
# refusing on "I could not tell" would block publishing for a reason that is
# not evidence of anything.
# `|| true` for the same pipefail reason, and it matters more here: with no
# cargo on PATH the pipeline returns 127 and, without this, the script died
# with NO output at all -- the exact silent-death failure this review round is
# about. Verified by running it with cargo removed from PATH. An empty result
# is a real, expected answer ("cannot tell"), and the branch below handles it.
INSTALLED_REV="$(cargo install --list 2>/dev/null \
    | grep -m1 'freenet-pointer-contract' \
    | grep -oE 'rev=[0-9a-f]+' | sed 's/rev=//' || true)"
if [ -z "$INSTALLED_REV" ]; then
    echo "WARNING: could not determine which revision of pointer-record is installed." >&2
    echo "         Expected $POINTER_TOOL_REV. Verification below is running against" >&2
    echo "         an unknown build of the tool that decides what a record's bytes are." >&2
elif [ "$INSTALLED_REV" != "$POINTER_TOOL_REV" ]; then
    echo "ERROR: pointer-record is at revision $INSTALLED_REV" >&2
    echo "       but this repo pins $POINTER_TOOL_REV." >&2
    echo "" >&2
    echo "CI verifies records with the pinned build. Publishing after verifying with" >&2
    echo "a different one means the check that passed here is not the check CI ran." >&2
    echo "Reinstall:" >&2
    echo "  cargo install --git https://github.com/freenet/freenet-migrate \\" >&2
    echo "    --rev $POINTER_TOOL_REV --features publish --locked freenet-pointer-contract" >&2
    exit 1
fi

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
elif ! grep -qxF "$AUTHOR_VK" FREENET.md; then
    # The CI gate checks this too, but it is NOT on the publish path --
    # Makefile.toml has sign-webapp depend on THIS script, not on
    # check-pointer-freshness. So without this, a FREENET.md/registry key
    # mismatch has no backstop at the one moment it becomes permanent.
    # Integrators take the author key from FREENET.md; if the two disagree,
    # every record we sign is one they will reject, and it looks fine from here.
    echo "ERROR: $TOML_PATH publishes author_verifying_key" >&2
    echo "       $AUTHOR_VK" >&2
    echo "       but FREENET.md does not publish that value on a line of its own." >&2
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
echo "NEXT, and promptly: this publish retires the delegate the pointer currently"
echo "names, so from the moment it completes until you run"
echo "  scripts/publish-pointer-records.sh"
echo "an integrator resolving the pointer derives a DEAD key. The record must be"
echo "published second -- its check [2] refuses a record naming a delegate that is"
echo "not already live -- so the window cannot be avoided, only kept short."
