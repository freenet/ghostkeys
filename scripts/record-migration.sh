#!/bin/bash
# Record the delegate WASM's hash in legacy_delegates.toml ON THE REMOTE, and
# prove it is there before anything gets published.
#
# Why this script is not just an append:
#
# `legacy_delegates.toml` is the only thing that carries a user's ghost keys
# across a delegate re-key -- the vault's migration sweep probes exactly the
# delegates listed in it, and nothing else. A published delegate whose entry
# never reaches the shared branch therefore becomes silently unreachable
# storage for every user who ran it. That is not hypothetical: on 2026-08-03
# the live delegate's entry sat in a working tree that reached no branch at
# all (see a2a1cef / ghostkeys#15).
#
# The fix has arrived in two steps, and this is the second:
#
#   1. #28 made this script COMMIT the record instead of printing "remember to
#      commit". That closed the working-tree window and left one behind, which
#      its own comment named: committed-but-never-pushed. It could only warn.
#   2. This version removes that window too, by making the REMOTE branch the
#      thing being edited. There is no interval in which the record exists only
#      on the publisher's machine, because the record is never created there.
#
# No CI check can substitute. A push- or PR-triggered job only ever sees what
# was pushed, so the state "it never left a laptop" is invisible to it by
# construction (ghostkeys#29). The mechanism has to live where the record is
# made.
#
# How it works, and why this shape:
#
# The commit is built with plumbing directly on top of the fetched tip of
# origin/main, then pushed there. Nothing about the operator's checkout is
# consulted or modified -- not the branch, not HEAD, not the index, not the
# working tree. That is deliberate, because every one of the states that used
# to need special handling stops existing:
#
#   - a dirty working tree cannot leak into the commit: the tree is built from
#     the remote's tree with exactly one blob replaced, and that is asserted
#     before the push, not merely intended;
#   - a detached HEAD is fine (#28 had to refuse it -- a commit there would
#     have been unreachable; here the commit is not made there);
#   - a local branch behind origin, or a feature branch, is fine: the record
#     goes to the branch that matters rather than to wherever the operator
#     happens to be standing. Committing onto a feature branch would just move
#     the human follow-up from "push" to "get the PR merged", which is the same
#     bug wearing a different hat.
#
# The push is fast-forward-only from the tip we fetched, so it can never
# clobber concurrent work; if main moved underneath us the push is rejected and
# we rebuild on the new tip and retry. There is no `--force` anywhere, and
# adding one would defeat the guarantee.
#
# Nothing here trusts an exit code as evidence: after pushing we re-fetch and
# read the file back out of the remote's branch, and (when `gh` is available)
# ask GitHub's API independently.
#
# Usage:
#   scripts/record-migration.sh                 record, push, verify
#   scripts/record-migration.sh --verify-only   only assert the record is on
#                                               the remote; changes nothing
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LEGACY="legacy_delegates.toml"
WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"

# Overridable so the test harness can point at a throwaway bare repo. Defaults
# are the real thing; there is deliberately no switch that turns the push off,
# because an opt-out is how this ends up not running on the one publish that
# mattered.
REMOTE="${GHOSTKEYS_RECORD_REMOTE:-origin}"
BRANCH="${GHOSTKEYS_RECORD_BRANCH:-main}"
PUSH_ATTEMPTS="${GHOSTKEYS_RECORD_PUSH_ATTEMPTS:-3}"

VERIFY_ONLY=0
case "${1:-}" in
    --verify-only) VERIFY_ONLY=1 ;;
    "") ;;
    *)
        echo "usage: $(basename "$0") [--verify-only]" >&2
        exit 2
        ;;
esac

die() {
    echo "" >&2
    echo "ERROR: $*" >&2
    echo "" >&2
    echo "The delegate's migration record is NOT on $REMOTE/$BRANCH." >&2
    echo "Do not publish until it is: users of the delegate this records would" >&2
    echo "have no migration path at the next re-key, and would lose access to" >&2
    echo "their ghost keys with no error shown." >&2
    exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- What we are recording ------------------------------------------------

if [ ! -f "$WASM" ]; then
    echo "ERROR: delegate WASM not found at $WASM" >&2
    echo "Run 'cargo make build-delegate' first." >&2
    exit 1
fi

CODE_HASH=$(b3sum --no-names "$WASM")
# BLAKE3 over the RAW BYTES of the code hash, not over its hex text. Empty
# parameters. check-migration re-derives this for every entry, so a mistake
# here fails the next PR rather than silently pointing the sweep at a delegate
# that never existed.
DELEGATE_KEY=$(printf '%s' "$CODE_HASH" | xxd -r -p | b3sum --no-names)

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    die "not a git repository, so the record cannot be pushed anywhere."
fi

# --- Reading the remote ---------------------------------------------------

# Fetch the branch and echo the sha it points at. Every read of "what is
# recorded" goes through here: the remote is the source of truth, not the
# local file. That is what makes this self-healing for the 2026-08-03 shape of
# failure -- a record that exists locally but nowhere else looks, correctly,
# like a record that does not exist.
fetch_tip() {
    if ! git fetch --no-tags --quiet "$REMOTE" "$BRANCH"; then
        die "could not fetch $BRANCH from $REMOTE (no network? no credentials?).
       Fix connectivity and re-run:  bash scripts/record-migration.sh"
    fi
    git rev-parse FETCH_HEAD
}

# Write the branch's copy of $LEGACY to $2.
remote_legacy() {
    if ! git show "$1:$LEGACY" >"$2" 2>/dev/null; then
        die "$REMOTE/$BRANCH has no $LEGACY at $1."
    fi
}

entry_recorded() {
    grep -qE "^code_hash *= *\"$CODE_HASH\"" "$1"
}

# The pair, adjacent and in order, which is how check-migration reads the file
# (positional pairing of code_hash and delegate_key lines). Verifying the two
# separately would pass on a file where they belong to different entries.
entry_pair_recorded() {
    grep -A1 -E "^code_hash *= *\"$CODE_HASH\"" "$1" |
        grep -qE "^delegate_key *= *\"$DELEGATE_KEY\""
}

code_hashes_of() {
    grep -oE '^code_hash *= *"[0-9a-f]{64}"' "$1" | grep -oE '[0-9a-f]{64}'
}

# --- Verification: read it back out of the remote -------------------------
#
# Deliberately not "the push exited 0". A push can succeed against the wrong
# remote, the wrong ref, or a ref someone rewrites a second later; the only
# statement worth making is that the branch, as the server currently serves
# it, contains the entry.
verify_on_remote() {
    local sha after
    sha=$(fetch_tip)
    after="$WORK/verify"
    remote_legacy "$sha" "$after"

    if ! entry_pair_recorded "$after"; then
        die "read $LEGACY back from $REMOTE/$BRANCH ($sha) and the entry is NOT there.
       Something rewrote the branch, or the push went somewhere else.
       Record it by hand before publishing:
         code_hash    = $CODE_HASH
         delegate_key = $DELEGATE_KEY"
    fi

    # The URL, not just the remote's name. "Verified on origin/main" is exactly
    # the sentence a fork or a mis-set remote would also produce, and believing
    # it is the failure this script exists to prevent.
    echo "Verified on $BRANCH at $(git remote get-url "$REMOTE" 2>/dev/null || echo "$REMOTE") ($sha):"
    echo "  $LEGACY contains code_hash $CODE_HASH"

    # An independent second opinion over a different transport, when we can get
    # one. Advisory: the fetch above already read the branch from the server,
    # so a flaky API call should not fail a publish.
    gh_crosscheck "$after"
}

gh_crosscheck() {
    local url slug body
    command -v gh >/dev/null 2>&1 || return 0
    url=$(git remote get-url "$REMOTE" 2>/dev/null || true)
    case "$url" in
        *github.com*) ;;
        *) return 0 ;;
    esac
    slug=$(printf '%s' "$url" | sed -E 's#^.*github\.com[:/]+##; s#\.git$##')
    # Twice, a couple of seconds apart: the contents API is served from a cache
    # and can trail a push by a moment.
    local try
    for try in 1 2; do
        if body=$(gh api "repos/$slug/contents/$LEGACY?ref=$BRANCH" \
            -H "Accept: application/vnd.github.raw" 2>/dev/null) &&
            printf '%s\n' "$body" | grep -qE "^code_hash *= *\"$CODE_HASH\""; then
            echo "Cross-checked via the GitHub API: entry is present on $BRANCH."
            return 0
        fi
        [ "$try" -eq 1 ] && sleep 2
    done

    # Not fatal, deliberately. The fetch above already read this branch from the
    # server over git, which is the authoritative answer; the likeliest reason
    # to land here is API caching, and failing a publish on a stale cache would
    # be a new way to be wrong rather than a safeguard. Said loudly all the
    # same, because the other explanation is that the git answer was not what
    # it appeared to be.
    echo "" >&2
    echo "WARNING: the GitHub API did not show the entry on $BRANCH, though the" >&2
    echo "         git fetch did. Probably API caching. If it is still missing" >&2
    echo "         from https://github.com/$slug/blob/$BRANCH/$LEGACY in a" >&2
    echo "         minute, treat the record as NOT landed." >&2
}

# --- --verify-only --------------------------------------------------------

if [ "$VERIFY_ONLY" -eq 1 ]; then
    echo "Checking that the built delegate's record is on $REMOTE/$BRANCH..."
    echo "  code_hash    = $CODE_HASH"
    echo "  delegate_key = $DELEGATE_KEY"
    verify_on_remote
    exit 0
fi

# --- Record it ------------------------------------------------------------

BASE_SHA=""
NEW_COMMIT=""
attempt=1
while :; do
    BASE_SHA=$(fetch_tip)
    BASE_FILE="$WORK/base"
    remote_legacy "$BASE_SHA" "$BASE_FILE"

    if entry_recorded "$BASE_FILE"; then
        # Idempotent: nothing appended, no empty commit, no push. Reached on a
        # re-run, and also when a concurrent publish recorded the same hash
        # while we were retrying.
        echo "Delegate hash is already recorded on $REMOTE/$BRANCH:"
        echo "  code_hash    = $CODE_HASH"
        echo "  delegate_key = $DELEGATE_KEY"
        NEW_COMMIT=""
        break
    fi

    # Build the new file content from the REMOTE's copy, so nothing from the
    # working tree can ride along.
    NEW_FILE="$WORK/new"
    cp "$BASE_FILE" "$NEW_FILE"
    # A file not ending in a newline would otherwise get the comment glued onto
    # its last line.
    if [ -s "$NEW_FILE" ] && [ -n "$(tail -c1 "$NEW_FILE")" ]; then
        echo "" >>"$NEW_FILE"
    fi
    {
        echo ""
        echo "# Added $(date +%Y-%m-%d) (recorded at publish)"
        echo "[[entry]]"
        echo "code_hash = \"$CODE_HASH\""
        echo "delegate_key = \"$DELEGATE_KEY\""
    } >>"$NEW_FILE"

    BLOB=$(git hash-object -w -- "$NEW_FILE")
    MODE=$(git ls-tree "$BASE_SHA" -- "$LEGACY" | awk '{print $1}')
    [ -n "$MODE" ] || MODE=100644

    # A scratch index, so the operator's real index is neither read nor
    # written. This is the step that makes "stage only legacy_delegates.toml"
    # a structural property instead of a discipline.
    IDX="$WORK/index"
    rm -f "$IDX"
    GIT_INDEX_FILE="$IDX" git read-tree "$BASE_SHA"
    GIT_INDEX_FILE="$IDX" git update-index --add --cacheinfo "$MODE,$BLOB,$LEGACY"
    TREE=$(GIT_INDEX_FILE="$IDX" git write-tree)

    cat >"$WORK/msg" <<EOF
chore: record the published delegate hash ${CODE_HASH:0:12}

Written by scripts/record-migration.sh during \`cargo make publish-ghostkeys\`.

code_hash    = $CODE_HASH
delegate_key = $DELEGATE_KEY

The vault's migration sweep only probes delegates listed in
$LEGACY, so this entry is what keeps ghost keys stored under this
delegate reachable across the next re-key.
EOF

    if ! NEW_COMMIT=$(git commit-tree "$TREE" -p "$BASE_SHA" -F "$WORK/msg" 2>"$WORK/err"); then
        die "could not create the commit: $(cat "$WORK/err")
       If this is about identity, set one and re-run:
         git config user.name  '<your name>'
         git config user.email '<your email>'"
    fi

    # By construction the tree differs from the base in one blob. Asserted
    # anyway: this is the claim the whole design rests on, and a bug in the
    # plumbing above would otherwise put unrelated content on main under a
    # message that says "record the published delegate hash".
    CHANGED=$(git diff --name-only "$BASE_SHA" "$NEW_COMMIT")
    if [ "$CHANGED" != "$LEGACY" ]; then
        die "refusing to push: the commit touches more than $LEGACY:
$(printf '%s\n' "$CHANGED" | sed 's/^/         /')"
    fi

    # Fast-forward-only by construction: the parent is the tip we just
    # fetched, so a rejection means the branch moved, never that we are about
    # to overwrite someone.
    if git push --quiet "$REMOTE" "$NEW_COMMIT:refs/heads/$BRANCH" 2>"$WORK/pusherr"; then
        break
    fi

    if [ "$attempt" -ge "$PUSH_ATTEMPTS" ]; then
        die "push to $REMOTE/$BRANCH was rejected $attempt time(s):

$(sed 's/^/         /' "$WORK/pusherr")

       Nothing has been published. Get this entry onto $BRANCH first --
       if the branch is protected, open a PR containing exactly:

         # Added $(date +%Y-%m-%d) (recorded at publish)
         [[entry]]
         code_hash = \"$CODE_HASH\"
         delegate_key = \"$DELEGATE_KEY\"

       then re-run the publish. It will see the entry and skip straight past
       this step."
    fi

    echo "Push rejected (attempt $attempt/$PUSH_ATTEMPTS); $BRANCH moved. Rebuilding on the new tip."
    attempt=$((attempt + 1))
done

if [ -n "$NEW_COMMIT" ]; then
    echo "Recorded the published delegate hash on $REMOTE/$BRANCH:"
    echo "  code_hash    = $CODE_HASH"
    echo "  delegate_key = $DELEGATE_KEY"
    echo "  commit       = ${NEW_COMMIT:0:12} (parent ${BASE_SHA:0:12})"
fi

verify_on_remote

# --- Bring the local checkout along, if that is safe ----------------------
#
# Convenience only; the record is already safe by this point. Anything
# uncertain is reported rather than resolved, because this runs in the middle
# of a publish and quietly changing files underneath a build is worse than a
# stale local copy.
TIP=$(git rev-parse FETCH_HEAD)
CUR_BRANCH=$(git symbolic-ref -q --short HEAD || true)

if [ "$CUR_BRANCH" = "$BRANCH" ] && git merge-base --is-ancestor "$TIP" HEAD 2>/dev/null; then
    echo "Local '$BRANCH' already contains the record."
elif [ "$CUR_BRANCH" = "$BRANCH" ] &&
    git merge-base --is-ancestor HEAD "$TIP" 2>/dev/null &&
    [ "$(git diff --name-only HEAD "$TIP")" = "$LEGACY" ] &&
    git diff HEAD --quiet -- "$LEGACY"; then
    # `|| true`: the record is already safe on the remote, so a checkout that
    # refuses to move (a lock, a hook, a staged change git objects to) is worth
    # a note and nothing more. Failing here would report a failure for an
    # operation that succeeded, which is its own kind of dangerous.
    if git merge --ff-only --quiet "$TIP" 2>/dev/null; then
        echo "Local '$BRANCH' fast-forwarded to $(git rev-parse --short HEAD)."
    else
        echo "NOTE: could not fast-forward your checkout; the record is on"
        echo "      $REMOTE/$BRANCH regardless. Run 'git pull --ff-only' later."
    fi
else
    echo ""
    echo "NOTE: your checkout does not have this entry yet (that is fine -- the"
    echo "      record is on $REMOTE/$BRANCH, which is what protects users)."
    echo "      To pick it up:  git checkout $BRANCH && git pull --ff-only"
    if [ -n "$CUR_BRANCH" ] && [ "$CUR_BRANCH" != "$BRANCH" ]; then
        echo ""
        echo "      You are on '$CUR_BRANCH'. Merge or rebase onto $BRANCH before"
        echo "      opening a PR from it, or check-migration will correctly report"
        echo "      that the PR drops this entry."
    fi
fi

# --- Entries that exist only in this checkout -----------------------------
#
# Not fatal, and not swept into the commit either: pushing content nobody
# reviewed to $BRANCH is its own problem. But an entry that exists only here is
# the exact 2026-08-03 shape, so it gets said out loud rather than discovered
# at the next re-key.
if [ -f "$LEGACY" ]; then
    LOCAL_ONLY="$WORK/local_only"
    : >"$LOCAL_ONLY"
    REMOTE_NOW="$WORK/remote_now"
    remote_legacy "$TIP" "$REMOTE_NOW"
    while read -r h; do
        [ -n "$h" ] || continue
        grep -q "\"$h\"" "$REMOTE_NOW" || echo "  $h" >>"$LOCAL_ONLY"
    done < <(code_hashes_of "$LEGACY")

    if [ -s "$LOCAL_ONLY" ]; then
        echo ""
        echo "WARNING: your local $LEGACY has entries that are NOT on $REMOTE/$BRANCH:" >&2
        cat "$LOCAL_ONLY" >&2
        echo "Anyone running those delegates is protected only by this checkout." >&2
        echo "Get them onto $BRANCH (a PR is fine) before this machine is gone." >&2
    fi
fi
