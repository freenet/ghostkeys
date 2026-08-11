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
#   scripts/record-migration.sh --preflight     assert this checkout is fit to
#                                               publish; changes nothing
#   scripts/record-migration.sh --verify-only   only assert the record is on
#                                               the remote; changes nothing
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LEGACY="legacy_delegates.toml"
WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"

# Overridable so the test harness can point at a throwaway bare repo. There is
# deliberately no switch that turns the push OFF -- an opt-out is how this ends
# up not running on the one publish that mattered -- but a switch that
# REDIRECTS it is the same hazard in disguise: a stale
# `export GHOSTKEYS_RECORD_REMOTE=/tmp/...` left from a debugging session would
# send the record to a scratch repo and let the publish proceed, green. So
# redirecting requires saying so on purpose, and announces itself.
REMOTE="${GHOSTKEYS_RECORD_REMOTE:-origin}"
BRANCH="${GHOSTKEYS_RECORD_BRANCH:-main}"
PUSH_ATTEMPTS="${GHOSTKEYS_RECORD_PUSH_ATTEMPTS:-3}"
# Which repository the record must land in. $REMOTE alone is not evidence:
# `origin` is the FORK on the standard `gh repo fork` layout, and every check
# here -- push, read-back, API cross-check -- derives from that one URL, so a
# fork is entirely self-consistent while freenet/ghostkeys has nothing.
EXPECTED_SLUG="${GHOSTKEYS_RECORD_SLUG:-freenet/ghostkeys}"

case "$PUSH_ATTEMPTS" in
    '' | *[!0-9]* | 0)
        echo "ERROR: GHOSTKEYS_RECORD_PUSH_ATTEMPTS must be a positive integer" >&2
        exit 2
        ;;
esac

MODE=record
case "${1:-}" in
    --verify-only) MODE=verify ;;
    # Read-only, and run early (before the UI is built) so a checkout that
    # cannot safely publish says so before anything is compiled or signed.
    --preflight) MODE=preflight ;;
    "") ;;
    *)
        echo "usage: $(basename "$0") [--verify-only | --preflight]" >&2
        exit 2
        ;;
esac

# What to say after an error. Which sentence is true depends on where in the
# publish we are, and telling an operator "do not publish" about a delegate
# that is already live wastes the only minutes that matter.
DIE_TAIL="The delegate's migration record is NOT on $REMOTE/$BRANCH.
Do not publish until it is: users of the delegate this records would
have no migration path at the next re-key, and would lose access to
their ghost keys with no error shown."

if [ "$MODE" = verify ]; then
    DIE_TAIL="The delegate's migration record is NOT on $REMOTE/$BRANCH.
This check runs AFTER 'fdev network publish', so if the publish completed,
that delegate is LIVE AND UNRECORDED right now -- the 2026-08-03 state.
Get the entry onto $BRANCH immediately; do not wait for the next publish."
fi

die() {
    echo "" >&2
    echo "ERROR: $*" >&2
    echo "" >&2
    echo "$DIE_TAIL" >&2
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

# The artifact must come from the canonical (path-remapped) build. A bare
# `cargo build` writes to this exact path without the remap, and its hash is
# machine-specific — recording it would append a permanent, unremovable entry
# for a delegate nobody will ever run (the no-drop rule makes every entry
# forever), costing every user a 3s probe per vault load. Detection is
# unambiguous, measured (ghostkeys#34): the remapped build embeds
# `/cargo-registry`; a bare build embeds absolute $CARGO_HOME paths instead.
# `grep -a` rather than `strings`, as in build-delegate.sh: a guard gated on
# a binutils tool silently does not run on the one machine that lacks it.
if ! grep -a -q -F '/cargo-registry' "$WASM"; then
    die "the delegate WASM at $WASM was built WITHOUT the path remap, so its hash \
is machine-specific and is NOT what gets published. Recording it would add a \
permanent registry entry for a delegate nobody runs. Rebuild it the one \
canonical way:  cargo make build-delegate   (see ghostkeys#34)"
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

# --- Is this the right repository? ----------------------------------------
#
# Before anything touches the network. Everything downstream -- the push, the
# read-back, even the GitHub cross-check's slug -- is derived from this one
# URL, so a fork is self-consistent: it would report "Verified on main at
# <fork>" while freenet/ghostkeys still has nothing. A URL that names a
# GitHub repository is checkable, so check it rather than printing it and
# hoping the operator reads carefully at the end of a publish.
REMOTE_URL=$(git remote get-url "$REMOTE" 2>/dev/null || true)
if [ -z "$REMOTE_URL" ]; then
    die "no remote named '$REMOTE' in this checkout."
fi
REDIRECTED=0
if [ -n "${GHOSTKEYS_RECORD_REMOTE:-}" ] ||
    [ -n "${GHOSTKEYS_RECORD_BRANCH:-}" ] ||
    [ -n "${GHOSTKEYS_RECORD_SLUG:-}" ]; then
    REDIRECTED=1
fi

if [ "$REDIRECTED" -eq 1 ]; then
    # Deliberate redirection has to be deliberate twice, because the dangerous
    # version of it is an environment variable nobody remembers exporting.
    if [ "${GHOSTKEYS_RECORD_TEST:-}" != "1" ]; then
        die "GHOSTKEYS_RECORD_REMOTE/_BRANCH/_SLUG is set, which sends the record
       somewhere other than $EXPECTED_SLUG. If that is deliberate, set
       GHOSTKEYS_RECORD_TEST=1 as well. If it is not -- a leftover export from
       a debugging session is the usual cause -- unset it:
         unset GHOSTKEYS_RECORD_REMOTE GHOSTKEYS_RECORD_BRANCH GHOSTKEYS_RECORD_SLUG"
    fi
    echo "############################################################"
    echo "# REDIRECTED: this run does NOT record to $EXPECTED_SLUG."
    echo "#   remote: $REMOTE ($REMOTE_URL)"
    echo "#   branch: $BRANCH"
    echo "# Nothing published from this run is protected on the real"
    echo "# repository. This is for testing only."
    echo "############################################################"

    # Redirection is for throwaway local repositories. A redirect that still
    # points at a GitHub repository is a fork, not a fixture, and recording a
    # real delegate there is the fork hazard with the guard switched off.
    case "$REMOTE_URL" in
        *github.com*)
            ACTUAL_SLUG=$(printf '%s' "$REMOTE_URL" |
                sed -E 's#^.*github\.com[:/]+##; s#\.git$##; s#/$##')
            if [ "$ACTUAL_SLUG" != "$EXPECTED_SLUG" ]; then
                die "redirected to '$ACTUAL_SLUG' on GitHub, which is not $EXPECTED_SLUG.
       Recording there would protect nobody: the vault ships the table from
       $EXPECTED_SLUG, and a fork's copy is invisible to every user.
       If you really mean that repository, name it in GHOSTKEYS_RECORD_SLUG."
            fi
            ;;
    esac
else
    # The default path, and the one that matters. Printing the URL and trusting
    # the operator to notice is what this script's own header calls a reminder
    # rather than a mechanism, so assert it instead.
    case "$REMOTE_URL" in
        *github.com[:/]"$EXPECTED_SLUG" | *github.com[:/]"$EXPECTED_SLUG".git | \
            *github.com[:/]"$EXPECTED_SLUG"/) ;;
        *)
            die "remote '$REMOTE' is '$REMOTE_URL', which is not $EXPECTED_SLUG.
       Recording there would protect nobody: the vault ships the table from
       $EXPECTED_SLUG, and a fork's copy is invisible to every user.
       Point '$REMOTE' at git@github.com:$EXPECTED_SLUG.git (a fork's clone
       usually calls the canonical repository 'upstream'), or set
       GHOSTKEYS_RECORD_REMOTE plus GHOSTKEYS_RECORD_TEST=1 if you really mean
       somewhere else."
            ;;
    esac
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

# Is CODE_HASH recorded in $1 together with its matching delegate_key?
#
# "Together" means the next delegate_key line after it, which is how both real
# consumers read the file: ui/build.rs parses [[entry]] blocks, and
# check-migration pairs the two line types positionally. Checking for the two
# lines independently would accept a file where they belong to different
# entries -- an entry pointing at a delegate that never existed, which is the
# silent hole the table exists to prevent.
#
# ONE predicate, used both to decide "already recorded?" and to verify the
# push. They must not disagree: a stricter verifier than recorder is an
# unrecoverable publish block (the recorder short-circuits, the verifier then
# rejects, and no re-run can clear it), and the reverse silently accepts a
# record it never really made. So tolerate a comment or blank line between the
# pair, as the format itself does.
#
# awk, not `grep -A1 | grep -q`: under `set -o pipefail` the downstream `grep
# -q` exits at first match and can SIGPIPE the upstream one, turning a present
# record into a spurious "NOT there" after a successful push.
entry_pair_recorded() {
    awk -v want="$CODE_HASH" -v key="$DELEGATE_KEY" '
        /^[[:space:]]*code_hash[[:space:]]*=/ {
            pending = (index($0, want) > 0)
            next
        }
        pending && /^[[:space:]]*delegate_key[[:space:]]*=/ {
            if (index($0, key) > 0) { ok = 1; exit }
            pending = 0
        }
        END { exit ok ? 0 : 1 }
    ' "$1"
}

code_hashes_of() {
    grep -oE '^[[:space:]]*code_hash[[:space:]]*=[[:space:]]*"[0-9a-f]{64}"' "$1" |
        grep -oE '[0-9a-f]{64}'
}

# --- The direction that protects the ARTIFACT -----------------------------
#
# Everything else here is about getting the record onto the branch. This is the
# opposite direction, and it is not symmetric bookkeeping -- it is what stops
# this design from relocating the very bug it fixes.
#
# ui/build.rs compiles legacy_delegates.toml FROM THE WORKING TREE into the
# webapp bundle (LEGACY_DELEGATES, read by ui/src/migration.rs). So the table
# that actually sweeps a user's ghost keys is the one in THIS checkout at build
# time, not the one on main. Push the record to main only, and a checkout that
# is merely BEHIND main -- no feature branch needed -- builds and signs a
# bundle whose table is missing entries main already has. Users running those
# delegates are orphaned by the publish, silently.
#
# check-migration cannot catch it: it compares against `git merge-base HEAD
# origin/main`, so entries added to main after the branch point are not in its
# base and can never register as dropped. Correct for reviewing a PR, vacuous
# as a publish gate.
#
# Fatal, not a warning. The bundle is already built by the time this runs; the
# only safe move is to stop before it is published.
assert_local_table_covers() { # $1 = the remote branch's copy
    local missing="$WORK/missing"
    : >"$missing"

    if [ ! -f "$LEGACY" ]; then
        DIE_TAIL="Nothing was published."
        die "$LEGACY is missing from this checkout, but ui/build.rs compiles it
       into the bundle. Restore it before publishing."
    fi

    while read -r h; do
        [ -n "$h" ] || continue
        grep -q "\"$h\"" "$LEGACY" || echo "  $h" >>"$missing"
    done < <(code_hashes_of "$1")

    if [ -s "$missing" ]; then
        DIE_TAIL="Nothing has been published, and nothing was recorded."
        die "this checkout's $LEGACY is missing $(wc -l <"$missing" | tr -d ' ') entry/entries
       that $REMOTE/$BRANCH already has:

$(cat "$missing")

       The webapp bundle compiles this file in (ui/build.rs), so the sweep
       table users get is the one in THIS checkout. Publishing it would leave
       everyone running those delegates with no migration path.

       Update and rebuild, then re-run:
         git checkout $BRANCH && git pull --ff-only
         cargo make publish-ghostkeys"
    fi
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
       Record it by hand:
         code_hash    = $CODE_HASH
         delegate_key = $DELEGATE_KEY"
    fi

    # The URL, not just the remote's name. "Verified on origin/main" is exactly
    # the sentence a fork would also produce. The slug assertion above is what
    # actually rules that out; this makes the answer legible.
    echo "Verified on $BRANCH at $REMOTE_URL ($sha):"
    echo "  $LEGACY contains code_hash $CODE_HASH"

    # An independent second opinion over a different transport, when we can get
    # one. Advisory: the fetch above already read the branch from the server,
    # so a flaky API call should not fail a publish.
    gh_crosscheck "$after"
}

gh_crosscheck() {
    local slug body
    command -v gh >/dev/null 2>&1 || return 0
    case "$REMOTE_URL" in
        *github.com*) ;;
        *) return 0 ;;
    esac
    # EXPECTED_SLUG, not one re-derived from the remote: asking the same
    # possibly-wrong URL a second way is not a second opinion. The two are
    # already asserted equal above, so this only matters if someone bypasses
    # that with GHOSTKEYS_RECORD_SLUG.
    slug="$EXPECTED_SLUG"
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

if [ "$MODE" = verify ]; then
    echo "Checking that the built delegate's record is on $REMOTE/$BRANCH..."
    echo "  code_hash    = $CODE_HASH"
    echo "  delegate_key = $DELEGATE_KEY"
    verify_on_remote
    exit 0
fi

# --- Can this checkout safely publish at all? -----------------------------
#
# Both directions get checked, and this one comes first because it decides
# whether the bundle is fit to ship, not merely whether the bookkeeping is
# tidy. Running it before any push also means a checkout that fails here
# leaves the branch untouched.
PRE_SHA=$(fetch_tip)
remote_legacy "$PRE_SHA" "$WORK/preflight"
assert_local_table_covers "$WORK/preflight"

if [ "$MODE" = preflight ]; then
    echo "Preflight OK: this checkout's $LEGACY covers every entry on $REMOTE/$BRANCH"
    echo "($PRE_SHA), so the bundle built from it will sweep them all."
    echo "Delegate about to be recorded at publish:"
    echo "  code_hash    = $CODE_HASH"
    echo "  delegate_key = $DELEGATE_KEY"
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

    # The same predicate the verification uses -- see entry_pair_recorded.
    if entry_pair_recorded "$BASE_FILE"; then
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
    {
        # This leading blank line also terminates a last line that lacked a
        # newline, so the comment below cannot end up glued onto it.
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
    echo "NOTE: your checkout does not have this entry yet. That is expected --"
    echo "      it names the delegate this very bundle ships, so the bundle does"
    echo "      not need to sweep it. (The entries the bundle DOES need were"
    echo "      checked before recording; see the preflight above.)"
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
