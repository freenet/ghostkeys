#!/bin/bash
# Append the just-published delegate WASM's hash to legacy_delegates.toml, and
# COMMIT it.
#
# The commit is the point. This script used to append and print "remember to
# commit", and on 2026-08-03 exactly that append sat uncommitted while the
# delegate it named was live -- one lost checkout away from a migration table
# with no entry for the delegate every user was running, i.e. silently
# unreachable ghostkeys.
#
# A reminder is not a mechanism, and the obvious backstop does not work either:
# a guard that looks for a dirty working tree can only fire on the publisher's
# machine, because a CI checkout is pristine by construction and cannot
# reproduce the state. So the fix is to remove the window rather than to watch
# it. Committing here means there is no interval in which the record exists
# only in someone's working tree.
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

# Commit only this file. The publish may have left other things dirty, and
# sweeping them into a commit labelled as a migration record is how a commit
# message ends up describing work it does not contain.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "" >&2
    echo "WARNING: not a git repository, so the record could NOT be committed." >&2
    echo "Commit legacy_delegates.toml by hand before the next delegate change," >&2
    echo "or users of the delegate just published will have no migration path." >&2
    exit 0
fi

# A detached HEAD would commit onto something no branch points at: the commit
# succeeds, this script reports success, and the record is unreachable. That is
# indistinguishable from the failure it exists to prevent, so refuse instead.
if ! BRANCH=$(git symbolic-ref -q --short HEAD); then
    echo "" >&2
    echo "ERROR: HEAD is detached, so a commit here would be unreachable." >&2
    echo "Check out a branch and re-run, or record legacy_delegates.toml by hand." >&2
    exit 1
fi

git add legacy_delegates.toml
if git diff --cached --quiet -- legacy_delegates.toml; then
    echo "Nothing to commit; the record was already in the tree."
    exit 0
fi

git commit -q -m "chore: record the published delegate hash ${CODE_HASH:0:12}" \
    -- legacy_delegates.toml
echo "Committed the record on '$BRANCH'."

# Committed-but-unpushed is now the most likely way for this to go wrong, so
# say so at the moment it is true rather than leaving it to be discovered at
# the next re-key.
UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)
if [ -z "$UPSTREAM" ]; then
    echo "WARNING: '$BRANCH' has no upstream, so nothing will push it." >&2
    echo "Push it before the next delegate change." >&2
elif [ "$(git rev-list --count "$UPSTREAM..HEAD" 2>/dev/null || echo 0)" -gt 0 ]; then
    echo "WARNING: '$BRANCH' is ahead of $UPSTREAM; the record is committed but NOT pushed." >&2
    echo "Push it before the next delegate change, or users of the delegate just" >&2
    echo "published will have no migration path." >&2
fi
