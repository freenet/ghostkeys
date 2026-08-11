#!/bin/bash
# Verify that no user can be orphaned by this delegate change.
#
# What actually protects users is that the delegate key they are running RIGHT
# NOW is still listed in legacy_delegates.toml, because that table is what the
# vault's migration sweep probes. The key users are running is normally the
# last entry recorded on the base branch -- `record-migration` puts every hash
# on main as part of `publish-ghostkeys`. Note it records just BEFORE the
# publish goes out, so strictly the tail is the last hash recorded at publish
# time; if that publish then failed, it names a delegate never deployed. Only
# informational output below depends on the distinction, never a safety
# decision.
#
# So the invariant checked here is: *this change drops no previously-recorded
# entry*. It deliberately does NOT require the newly-built hash to be recorded.
#
# That used to be the check, and it was backwards (ghostkeys#10): a PR cannot
# record its own post-publish hash, because it has not published yet -- and the
# CI runner's WASM bytes differ from a local build anyway (ghostkeys#9), so
# whatever a developer recorded pre-publish would not even be the hash CI
# computes. The result was a guard that failed exactly when you followed its
# own documented order, and that people would have learned to route around.
#
# The successor's hash is recorded by `record-migration` at publish time, from
# the WASM that is about to ship -- the only moment it is knowable and the only
# moment it matters.
#
# Usage:
#   scripts/check-migration.sh [BASE_LEGACY_TOML]
#
# BASE_LEGACY_TOML is the base branch's copy of legacy_delegates.toml. CI passes
# it explicitly. Run locally without it and the script finds the merge base with
# origin/main itself; if it cannot, it says so and checks what it still can.
set -euo pipefail

WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"
LEGACY="legacy_delegates.toml"
BASE_LEGACY="${1:-}"

if [ ! -f "$WASM" ]; then
    echo "ERROR: delegate WASM not found at $WASM" >&2
    echo "Run 'cargo make build-delegate' first." >&2
    exit 1
fi

# --- The artifact must come from the canonical (path-remapped) build ------
#
# This script hashes a WASM it does not build. A bare `cargo build` writes to
# the exact same path WITHOUT the registry path remap, and its hash is
# machine-specific — a value the publish path never produces (ghostkeys#34:
# same source, same toolchain, two different "delegate hashes", and PR #32
# recorded the wrong one). The two states are unambiguous, measured: the
# remapped build embeds `/cargo-registry` (and no absolute $CARGO_HOME paths,
# which build-delegate.sh separately refuses); a bare build is the exact
# inverse.
#
# `grep -a` rather than `strings`, for the same reason build-delegate.sh uses
# it: gating a guard on a binutils tool means it silently does not run on the
# one machine that lacks it.
if ! grep -a -q -F '/cargo-registry' "$WASM"; then
    echo "ERROR: $WASM was built WITHOUT the path remap." >&2
    echo "Its hash is machine-specific and is NOT what gets published, so every" >&2
    echo "number this script would print about it is wrong. Rebuild it the one" >&2
    echo "canonical way:  cargo make build-delegate   (see ghostkeys#34)" >&2
    exit 1
fi

if [ ! -f "$LEGACY" ]; then
    echo "ERROR: $LEGACY not found" >&2
    exit 1
fi

# Every code_hash in a legacy_delegates.toml, in file order.
code_hashes_of() {
    grep -oE 'code_hash *= *"[0-9a-f]{64}"' "$1" | grep -oE '[0-9a-f]{64}'
}

# Every delegate_key, in file order. Paired positionally with the above, which
# holds because `add-migration` and `record-migration` always append the two
# lines together.
delegate_keys_of() {
    grep -oE 'delegate_key *= *"[0-9a-f]{64}"' "$1" | grep -oE '[0-9a-f]{64}'
}

CODE_HASH=$(b3sum --no-names "$WASM")
echo "Built delegate hash: $CODE_HASH"

# --- Every recorded entry must be internally consistent -------------------
#
# The delegate key is BLAKE3 over the raw bytes of the code hash (parameters
# are empty). A hand-edited or mistyped entry points the sweep at a delegate
# that never existed, so it probes, times out, and reports nothing wrong --
# a silent hole in exactly the table that exists to prevent silent holes.
#
# Read into arrays with a loop rather than `mapfile`: mapfile is bash 4+, and
# macOS still ships bash 3.2, so a developer running `cargo make
# check-migration` there would get "mapfile: command not found" instead of a
# migration check.
ALL_HASHES=()
while IFS= read -r line; do ALL_HASHES+=("$line"); done < <(code_hashes_of "$LEGACY")
ALL_KEYS=()
while IFS= read -r line; do ALL_KEYS+=("$line"); done < <(delegate_keys_of "$LEGACY")

if [ "${#ALL_HASHES[@]}" -eq 0 ]; then
    echo "ERROR: $LEGACY has no entries" >&2
    exit 1
fi

if [ "${#ALL_HASHES[@]}" -ne "${#ALL_KEYS[@]}" ]; then
    echo "ERROR: $LEGACY has ${#ALL_HASHES[@]} code_hash but ${#ALL_KEYS[@]} delegate_key values" >&2
    echo "Every entry needs both, appended together." >&2
    exit 1
fi

BAD=0
for i in "${!ALL_HASHES[@]}"; do
    EXPECTED=$(printf '%s' "${ALL_HASHES[$i]}" | xxd -r -p | b3sum --no-names)
    if [ "$EXPECTED" != "${ALL_KEYS[$i]}" ]; then
        echo "ERROR: entry $((i + 1)) is inconsistent." >&2
        echo "  code_hash    = ${ALL_HASHES[$i]}" >&2
        echo "  delegate_key = ${ALL_KEYS[$i]}" >&2
        echo "  expected     = $EXPECTED" >&2
        BAD=1
    fi
done
if [ "$BAD" -ne 0 ]; then
    echo "" >&2
    echo "delegate_key must be BLAKE3 over the raw bytes of code_hash." >&2
    echo "Do not hand-edit $LEGACY -- use 'cargo make add-migration'." >&2
    exit 1
fi
echo "OK: all ${#ALL_HASHES[@]} recorded entries are internally consistent."

# --- A previous publish's record must not still be uncommitted ------------
#
# On 2026-08-03 a published delegate's record sat uncommitted in a working
# tree while the delegate it named was live, so the next build would have
# shipped a migration table missing the delegate every user was actually
# running -- silently unreachable ghostkeys, which is the failure this whole
# table exists to prevent. Publishing again on top of an uncommitted record
# would bake the omission in, so refuse.
#
# `record-migration` no longer writes to the working tree at all, so it can no
# longer be the cause. What reaches this guard now is a hand-edit, or an
# `add-migration` append (the documented pre-change step) that has not been
# committed yet -- which is the ordinary way a human meets it, and the message
# below covers both.
#
# Scope, stated plainly because it is easy to mistake this for more than it is:
# this is a LOCAL, publish-time guard. It looks for a dirty working tree, and a
# CI checkout is pristine by construction -- no job step writes this file -- so
# in CI the condition cannot arise and this can never go red there. It runs in
# CI only because refusing to gate it costs nothing; it protects the publisher,
# not the pull request.
#
# The window it was written for is now CLOSED at the source, in two steps:
# `record-migration.sh` first learned to commit the record (#28), and then to
# create it on origin/main directly and read it back off the remote before the
# publish proceeds (ghostkeys#29). There is no longer an interval in which a
# published delegate's record exists only on the publisher's machine.
#
# What is left: publishing with `fdev network publish` directly, which runs
# none of this.
#
# One consequence of that no-drop rule is worth writing down, because it only
# ever accumulates. An abandoned publish (the record lands, then `fdev network
# publish` fails) leaves an entry for a delegate nobody ever ran, and this
# check then makes it permanent: no PR may remove it. Each such entry costs
# every user one bounded background probe (LEGACY_PROBE_TIMEOUT_SECS = 3s,
# ui/src/migration.rs) on every vault load, forever. That is the right trade --
# the alternative is losing ghost keys -- but it compounds, so a deliberate
# procedure for removing entries that can be PROVEN never to have been
# published (checked against the network, not against git) may eventually be
# needed. Removing one by hand today would simply fail this check, which is
# the correct default.
#
# A check that a pull request's recorded tail matches the delegate actually
# DEPLOYED would be a stronger gate still. It needs to read the published
# pointer from a node, which no CI job here can do, so it belongs in the
# publish/verify path. It does not exist yet.
if git rev-parse --git-dir >/dev/null 2>&1; then
    # `git diff HEAD`, not plain `git diff`: the latter compares against the
    # index, so `git add`-ing the record and stopping there would slip past
    # this check while leaving it just as uncommitted. Verified by staging one
    # and watching the guard pass.
    if ! git diff HEAD --quiet -- "$LEGACY" 2>/dev/null; then
        echo "ERROR: $LEGACY has uncommitted changes." >&2
        echo "" >&2
        echo "Usually that is an 'add-migration' append you have not committed yet, or" >&2
        echo "a hand-edit. Either way, an entry that exists only in this working tree" >&2
        echo "protects nobody: publishing would ship a migration table missing a" >&2
        echo "delegate that users are running, and their ghostkeys would go quietly" >&2
        echo "unreachable." >&2
        echo "" >&2
        echo "Commit $LEGACY (in a PR, if it is an add-migration entry), then re-run." >&2
        git --no-pager diff --stat -- "$LEGACY" >&2
        exit 1
    fi
fi

# --- Resolve the base branch's copy, if we can ----------------------------

CLEANUP_BASE=""
if [ -z "$BASE_LEGACY" ]; then
    if BASE_REF=$(git merge-base HEAD origin/main 2>/dev/null); then
        BASE_LEGACY=$(mktemp)
        CLEANUP_BASE="$BASE_LEGACY"
        # A base that predates the file leaves this empty, handled below.
        git show "$BASE_REF:$LEGACY" >"$BASE_LEGACY" 2>/dev/null || : >"$BASE_LEGACY"
        # shellcheck disable=SC2064  # expand now: the path must not change later
        trap "rm -f '$CLEANUP_BASE'" EXIT
    fi
fi

if [ -z "$BASE_LEGACY" ] || [ ! -s "$BASE_LEGACY" ]; then
    echo "NOTE: no base copy of $LEGACY available (no origin/main?)."
    echo "      Skipping the dropped-entry check -- the only check here that"
    echo "      catches orphaning users. CI runs it with an explicit base."
    LAST=$(code_hashes_of "$LEGACY" | tail -1)
    if [ "$CODE_HASH" = "$LAST" ]; then
        echo "OK: built delegate matches the last recorded entry -- nothing changed."
    else
        echo "OK: new delegate hash; migration will run from $LAST to $CODE_HASH."
    fi
    exit 0
fi

# --- The check that matters: no recorded entry may disappear --------------

# A plain counter and a temp file rather than an array: `${#arr[@]}` on an
# empty array errors under `set -u` in bash < 4.4 -- the same macOS case the
# loop above exists for.
MISSING_COUNT=0
MISSING_LIST="$(mktemp)"
while read -r h; do
    [ -n "$h" ] || continue
    if ! grep -q "\"$h\"" "$LEGACY"; then
        MISSING_COUNT=$((MISSING_COUNT + 1))
        echo "  missing: $h" >>"$MISSING_LIST"
    fi
done < <(code_hashes_of "$BASE_LEGACY")

if [ "$MISSING_COUNT" -ne 0 ]; then
    echo "::error::This change drops $MISSING_COUNT recorded delegate entry/entries."
    echo "::error::Every user still running one of them would be orphaned: the vault"
    echo "::error::only sweeps delegates listed in $LEGACY, so their ghostkeys become"
    echo "::error::unreachable with no error shown."
    cat "$MISSING_LIST"
    rm -f "$MISSING_LIST"
    exit 1
fi
rm -f "$MISSING_LIST"

BASE_LAST=$(code_hashes_of "$BASE_LEGACY" | tail -1)
echo "Deployed delegate hash (base branch tail): $BASE_LAST"

if [ "$CODE_HASH" = "$BASE_LAST" ]; then
    echo "OK: delegate WASM unchanged from base -- no migration needed."
    exit 0
fi

if grep -q "\"$CODE_HASH\"" "$LEGACY"; then
    echo "OK: built hash is already recorded (earlier entry)."
    exit 0
fi

echo "OK: delegate re-keys in this change."
echo "    Migration will run from $BASE_LAST to the published hash."
echo "    'cargo make publish-ghostkeys' records the published hash on"
echo "    origin/main itself, and refuses to publish if it cannot."
