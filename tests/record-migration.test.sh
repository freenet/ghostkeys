#!/bin/bash
# Tests for scripts/record-migration.sh.
#
# The script's job is to make a delegate's migration record reach the shared
# branch, or to fail loudly enough that nobody publishes without it. Both
# halves are worth testing, and the second half is the one that matters: a
# version of this script that quietly does nothing looks exactly like a
# version that works, right up until a re-key makes users' ghost keys
# unreachable. So most of what is below is about failure and about states the
# operator's checkout can be in.
#
# Everything runs against throwaway bare repositories on local disk -- no
# network, no GitHub -- via GHOSTKEYS_RECORD_REMOTE / _BRANCH. Concurrency and
# rejection are simulated with pre-receive hooks, which is what the server
# would actually use to reject a push.
#
# Run: bash tests/record-migration.test.sh   (or: cargo make test-scripts)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UNDER_TEST="$REPO_ROOT/scripts/record-migration.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
CASE=""

case_start() {
    CASE="$1"
    echo ""
    echo "=== $CASE"
}

ok() {
    PASS=$((PASS + 1))
    echo "  ok: $1"
}

bad() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1" >&2
}

check() { # check <description> <condition-exit-code-already-evaluated>
    if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi
}

SEED_LEGACY='# Legacy delegate entries for migration.

# Added 2026-01-01
[[entry]]
code_hash = "1111111111111111111111111111111111111111111111111111111111111111"
delegate_key = "2222222222222222222222222222222222222222222222222222222222222222"
'

# Build a fixture: a bare "remote" seeded with legacy_delegates.toml on main,
# plus a clone containing the script under test and a fake delegate WASM.
fixture() { # fixture <name> [wasm-bytes]
    local name="$1" wasm="${2:-delegate-bytes-v1}"
    local base="$TMP/$name"
    mkdir -p "$base"

    git init --quiet --bare -b main "$base/remote.git"

    git init --quiet -b main "$base/seed"
    (
        cd "$base/seed" || exit 1
        git config user.email t@example.com
        git config user.name Test
        printf '%s' "$SEED_LEGACY" >legacy_delegates.toml
        echo "readme" >README.md
        echo "other" >other.txt
        git add -A
        git commit --quiet -m "seed"
        git remote add origin "$base/remote.git"
        git push --quiet origin main
    ) || return 1

    git clone --quiet "$base/remote.git" "$base/work"
    (
        cd "$base/work" || exit 1
        git config user.email t@example.com
        git config user.name Test
        mkdir -p scripts target/wasm32-unknown-unknown/release
        cp "$UNDER_TEST" scripts/record-migration.sh
        printf '%s' "$wasm" >target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm
    ) || return 1

    echo "$base"
}

run_record() { # run_record <workdir> [args...]; stdout+stderr -> $OUT, status -> $STATUS
    local wd="$1"
    shift
    OUT="$(cd "$wd" && GHOSTKEYS_RECORD_REMOTE=origin GHOSTKEYS_RECORD_BRANCH=main \
        bash scripts/record-migration.sh "$@" 2>&1)"
    STATUS=$?
}

wasm_hash() { # wasm_hash <workdir>
    b3sum --no-names "$1/target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"
}

wasm_key() { # wasm_key <workdir>
    printf '%s' "$(wasm_hash "$1")" | xxd -r -p | b3sum --no-names
}

remote_file() { # remote_file <base>
    git -C "$1/remote.git" show main:legacy_delegates.toml 2>/dev/null
}

remote_sha() { # remote_sha <base>
    git -C "$1/remote.git" rev-parse main
}

for tool in b3sum xxd git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: '$tool' is required to run these tests." >&2
        exit 1
    fi
done

# --- 1. Happy path --------------------------------------------------------

case_start "clean checkout on main: records, pushes, verifies, fast-forwards"
B=$(fixture happy)
H=$(wasm_hash "$B/work")
K=$(wasm_key "$B/work")
BEFORE=$(remote_sha "$B")
run_record "$B/work"
check "exits 0" "$STATUS"
remote_file "$B" | grep -qE "^code_hash *= *\"$H\""
check "code_hash is on the remote branch" $?
remote_file "$B" | grep -A1 -E "^code_hash *= *\"$H\"" | grep -qE "^delegate_key *= *\"$K\""
check "delegate_key is paired with it, adjacent and in order" $?
[ "$(git -C "$B/remote.git" diff --name-only "$BEFORE" main)" = "legacy_delegates.toml" ]
check "the pushed commit touches only legacy_delegates.toml" $?
[ "$(git -C "$B/remote.git" rev-parse main^)" = "$BEFORE" ]
check "it is a fast-forward child of the previous tip (nothing clobbered)" $?
grep -qE "^code_hash *= *\"$H\"" "$B/work/legacy_delegates.toml"
check "local checkout was fast-forwarded to include it" $?
echo "$OUT" | grep -q "Verified on main at $B/remote.git"
check "reports reading the entry back off the remote, naming its URL" $?
echo "$OUT" | grep -q "$H"
check "prints the hash it verified" $?

# --- 2. Idempotency -------------------------------------------------------

case_start "re-run: no duplicate entry, no empty commit, no push"
AFTER_FIRST=$(remote_sha "$B")
run_record "$B/work"
check "exits 0" "$STATUS"
[ "$(remote_sha "$B")" = "$AFTER_FIRST" ]
check "remote branch is unchanged" $?
[ "$(remote_file "$B" | grep -cE "^code_hash *= *\"$H\"")" = "1" ]
check "the entry appears exactly once" $?
echo "$OUT" | grep -q "already recorded"
check "says it was already recorded" $?

# --- 3. Dirty working tree ------------------------------------------------

case_start "dirty tree with unrelated changes: none of it is committed"
B=$(fixture dirty)
H=$(wasm_hash "$B/work")
BEFORE=$(remote_sha "$B")
echo "UNRELATED EDIT" >>"$B/work/README.md"
echo "STAGED EDIT" >>"$B/work/other.txt"
git -C "$B/work" add other.txt                 # staged, to prove the index is not used
echo "secret" >"$B/work/untracked.txt"
run_record "$B/work"
check "exits 0" "$STATUS"
[ "$(git -C "$B/remote.git" diff --name-only "$BEFORE" main)" = "legacy_delegates.toml" ]
check "pushed commit touches only legacy_delegates.toml" $?
git -C "$B/remote.git" show main:README.md | grep -q "UNRELATED EDIT"
[ $? -ne 0 ]
check "the unrelated worktree edit did not reach the remote" $?
git -C "$B/remote.git" show main:other.txt | grep -q "STAGED EDIT"
[ $? -ne 0 ]
check "the STAGED unrelated edit did not reach the remote either" $?
git -C "$B/work" diff --quiet -- README.md
[ $? -ne 0 ]
check "the operator's dirty README is still dirty (nothing was committed for them)" $?
git -C "$B/work" diff --cached --quiet -- other.txt
[ $? -ne 0 ]
check "the operator's staged change is still staged" $?
[ -f "$B/work/untracked.txt" ]
check "the untracked file is untouched" $?

# --- 4. Detached HEAD -----------------------------------------------------

case_start "detached HEAD: still records (the commit is not made locally)"
B=$(fixture detached)
H=$(wasm_hash "$B/work")
git -C "$B/work" checkout --quiet --detach HEAD
run_record "$B/work"
check "exits 0" "$STATUS"
remote_file "$B" | grep -qE "^code_hash *= *\"$H\""
check "entry is on the remote branch" $?

# --- 5. Feature branch, local main behind --------------------------------

case_start "publishing from a feature branch: the record still goes to main"
B=$(fixture feature)
H=$(wasm_hash "$B/work")
git -C "$B/work" checkout --quiet -b my-feature
echo "feature work" >>"$B/work/README.md"
git -C "$B/work" commit --quiet -am "feature commit"
run_record "$B/work"
check "exits 0" "$STATUS"
remote_file "$B" | grep -qE "^code_hash *= *\"$H\""
check "entry is on main, not on the feature branch" $?
git -C "$B/remote.git" show main:README.md | grep -q "feature work"
[ $? -ne 0 ]
check "the feature branch's own commit was not pushed along with it" $?
echo "$OUT" | grep -q "my-feature"
check "warns that the checkout is on another branch" $?

# --- 6. Concurrent push: main moves between our fetch and our push --------

case_start "main moves mid-push: rejected, rebuilt on the new tip, no clobber"
B=$(fixture concurrent)
H=$(wasm_hash "$B/work")
# Someone else's commit, ready to land but not pushed yet.
git clone --quiet "$B/remote.git" "$B/other"
(
    cd "$B/other" || exit 1
    git config user.email t@example.com
    git config user.name Test
    echo "someone else's work" >rival.txt
    git add rival.txt
    git commit --quiet -m "rival commit"
)
# A client-side pre-push hook is the only honest way to land it in the window
# between our fetch and our push: a server-side pre-receive hook cannot move a
# ref at all ("ref updates forbidden inside quarantine environment"), so a
# simulation built on one would prove nothing. This lands the rival commit and
# then lets our push go through to the server, which rejects it as a genuine
# non-fast-forward -- the real thing, not a stand-in for it.
cat >"$B/work/.git/hooks/pre-push" <<EOF
#!/bin/bash
if [ ! -f "$B/raced-once" ]; then
    touch "$B/raced-once"
    git -C "$B/other" push --quiet origin main
fi
exit 0
EOF
chmod +x "$B/work/.git/hooks/pre-push"
run_record "$B/work"
RIVAL=$(git -C "$B/other" rev-parse HEAD)
check "exits 0 after retrying" "$STATUS"
echo "$OUT" | grep -q "Push rejected (attempt 1/3)"
check "reports the rejection and the retry" $?
remote_file "$B" | grep -qE "^code_hash *= *\"$H\""
check "entry is on main" $?
git -C "$B/remote.git" show main:rival.txt | grep -q "someone else's work"
check "the concurrent commit survived (no force, no clobber)" $?
[ "$(git -C "$B/remote.git" rev-parse main^)" = "$RIVAL" ]
check "our commit was rebuilt on top of the new tip" $?

# --- 7. Push permanently rejected ----------------------------------------

case_start "push always rejected (e.g. a protected branch): fails loudly"
B=$(fixture rejected)
H=$(wasm_hash "$B/work")
K=$(wasm_key "$B/work")
BEFORE=$(remote_sha "$B")
cat >"$B/remote.git/hooks/pre-receive" <<'EOF'
#!/bin/bash
echo "remote: refusing to update a protected branch" >&2
exit 1
EOF
chmod +x "$B/remote.git/hooks/pre-receive"
run_record "$B/work"
[ "$STATUS" -ne 0 ]
check "exits NON-zero, so a publish wrapped in 'set -e' aborts" $?
[ "$(remote_sha "$B")" = "$BEFORE" ]
check "remote branch is unchanged" $?
echo "$OUT" | grep -q "Do not publish until it is"
check "says not to publish" $?
echo "$OUT" | grep -q "$H"
check "prints the code_hash the operator must record by hand" $?
echo "$OUT" | grep -q "$K"
check "prints the delegate_key too" $?
echo "$OUT" | grep -q "open a PR"
check "gives the branch-protected recovery route" $?

# --- 8. Unreachable remote -----------------------------------------------

case_start "unreachable remote: fails loudly rather than recording nowhere"
B=$(fixture unreachable)
git -C "$B/work" remote set-url origin "$TMP/does-not-exist.git"
run_record "$B/work"
[ "$STATUS" -ne 0 ]
check "exits non-zero" $?
echo "$OUT" | grep -q "could not fetch"
check "names the problem" $?
git -C "$B/work" diff --quiet -- legacy_delegates.toml
check "left no half-written record in the working tree" $?

# --- 9. The 2026-08-03 shape: recorded locally, absent from the remote ----

case_start "record exists locally but not on the remote: re-records it"
B=$(fixture selfheal)
H=$(wasm_hash "$B/work")
BEFORE=$(remote_sha "$B")
run_record "$B/work"
check "first run exits 0" "$STATUS"
# Simulate the record having never reached the remote, while the local
# checkout believes it did.
git -C "$B/remote.git" update-ref refs/heads/main "$BEFORE"
remote_file "$B" | grep -qE "^code_hash *= *\"$H\""
[ $? -ne 0 ]
check "precondition: the remote no longer has the entry" $?
grep -qE "^code_hash *= *\"$H\"" "$B/work/legacy_delegates.toml"
check "precondition: the local checkout still does" $?
run_record "$B/work"
check "second run exits 0" "$STATUS"
remote_file "$B" | grep -qE "^code_hash *= *\"$H\""
check "the entry is back on the remote (local state is not trusted as proof)" $?

# --- 10. Entries that exist only in the checkout --------------------------

case_start "local-only entries are reported, and not silently pushed"
B=$(fixture localonly)
ORPHAN="abababababababababababababababababababababababababababababababab"
ORPHAN_KEY=$(printf '%s' "$ORPHAN" | xxd -r -p | b3sum --no-names)
{
    echo ""
    echo "[[entry]]"
    echo "code_hash = \"$ORPHAN\""
    echo "delegate_key = \"$ORPHAN_KEY\""
} >>"$B/work/legacy_delegates.toml"
git -C "$B/work" commit --quiet -am "locally committed, never pushed"
run_record "$B/work"
check "exits 0" "$STATUS"
echo "$OUT" | grep -q "$ORPHAN"
check "warns about the entry that exists only in this checkout" $?
remote_file "$B" | grep -q "$ORPHAN"
[ $? -ne 0 ]
check "does not push unreviewed local content to main" $?

# --- 11. --verify-only ----------------------------------------------------

case_start "--verify-only asserts remote state and changes nothing"
B=$(fixture verifyonly)
H=$(wasm_hash "$B/work")
BEFORE=$(remote_sha "$B")
run_record "$B/work" --verify-only
[ "$STATUS" -ne 0 ]
check "fails when the entry is not on the remote" $?
[ "$(remote_sha "$B")" = "$BEFORE" ]
check "recorded nothing (it is a read-only check)" $?
run_record "$B/work"
check "recording then exits 0" "$STATUS"
AFTER=$(remote_sha "$B")
run_record "$B/work" --verify-only
check "verify-only now passes" "$STATUS"
[ "$(remote_sha "$B")" = "$AFTER" ]
check "still changed nothing" $?

# --- 12. Missing WASM -----------------------------------------------------

case_start "no built delegate: refuses rather than recording a stale hash"
B=$(fixture nowasm)
rm "$B/work/target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"
run_record "$B/work"
[ "$STATUS" -ne 0 ]
check "exits non-zero" $?
echo "$OUT" | grep -q "delegate WASM not found"
check "says what is missing" $?

# --- 13. The direction that protects the published artifact ---------------
#
# ui/build.rs compiles legacy_delegates.toml from the WORKING TREE into the
# bundle, so a checkout that is behind main ships a sweep table missing entries
# main already has. Recording to main does nothing for those users -- this is
# the mirror image of the bug this script exists to fix, and the reason the
# check runs in both directions.

case_start "checkout behind main: refuses to publish, records nothing"
B=$(fixture behind)
H=$(wasm_hash "$B/work")
BEHIND_SHA=$(remote_sha "$B")
# An entry lands on main that this checkout has never seen.
git clone --quiet "$B/remote.git" "$B/ahead"
LOST="cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
LOST_KEY=$(printf '%s' "$LOST" | xxd -r -p | b3sum --no-names)
(
    cd "$B/ahead" || exit 1
    git config user.email t@example.com
    git config user.name Test
    {
        echo ""
        echo "[[entry]]"
        echo "code_hash = \"$LOST\""
        echo "delegate_key = \"$LOST_KEY\""
    } >>legacy_delegates.toml
    git commit --quiet -am "someone else's publish"
    git push --quiet origin main
)
AHEAD_SHA=$(remote_sha "$B")
run_record "$B/work"
[ "$STATUS" -ne 0 ]
check "exits non-zero, so the publish aborts before fdev runs" $?
echo "$OUT" | grep -q "$LOST"
check "names the entry the bundle would have shipped without" $?
echo "$OUT" | grep -q "ui/build.rs"
check "explains that the bundle compiles the local file in" $?
[ "$(remote_sha "$B")" = "$AHEAD_SHA" ]
check "recorded nothing on main (it stopped before pushing)" $?
remote_file "$B" | grep -qE "code_hash *= *\"$H\""
[ $? -ne 0 ]
check "the new hash was NOT recorded" $?
# And it clears once the checkout catches up.
git -C "$B/work" pull --quiet --ff-only
run_record "$B/work"
check "after 'git pull', the same publish is allowed" "$STATUS"
remote_file "$B" | grep -qE "code_hash *= *\"$H\""
check "and the record lands" $?

case_start "--preflight is read-only and catches the same state early"
B=$(fixture preflight)
BEFORE=$(remote_sha "$B")
run_record "$B/work" --preflight
check "passes on an up-to-date checkout" "$STATUS"
[ "$(remote_sha "$B")" = "$BEFORE" ]
check "pushed nothing (it is read-only)" $?
echo "$OUT" | grep -q "Preflight OK"
check "says so" $?
# Now put an entry on main that the checkout lacks.
git clone --quiet "$B/remote.git" "$B/ahead"
(
    cd "$B/ahead" || exit 1
    git config user.email t@example.com
    git config user.name Test
    printf '\n[[entry]]\ncode_hash = "%s"\ndelegate_key = "%s"\n' "$LOST" "$LOST_KEY" \
        >>legacy_delegates.toml
    git commit --quiet -am "someone else's publish"
    git push --quiet origin main
)
run_record "$B/work" --preflight
[ "$STATUS" -ne 0 ]
check "fails when the checkout is behind" $?

# --- 14. A hand-edited entry must not deadlock publishing -----------------
#
# The "already recorded?" question and the "did it land?" question have to be
# the same question. When they were not (code_hash-only vs adjacent-pair), an
# entry with a comment between its two lines made every run exit 1 -- the fast
# path skipped the append, the verifier then rejected -- and no re-run could
# clear it.

case_start "non-adjacent pair on main: no deadlock, no duplicate"
B=$(fixture nonadjacent)
H=$(wasm_hash "$B/work")
K=$(wasm_key "$B/work")
git clone --quiet "$B/remote.git" "$B/hand"
(
    cd "$B/hand" || exit 1
    git config user.email t@example.com
    git config user.name Test
    printf '\n[[entry]]\ncode_hash = "%s"\n# hand-written note\ndelegate_key = "%s"\n' \
        "$H" "$K" >>legacy_delegates.toml
    git commit --quiet -am "hand-edited entry"
    git push --quiet origin main
)
HAND_SHA=$(remote_sha "$B")
git -C "$B/work" pull --quiet --ff-only
run_record "$B/work"
check "exits 0 rather than blocking every future publish" "$STATUS"
[ "$(remote_sha "$B")" = "$HAND_SHA" ]
check "treats it as already recorded (no duplicate entry appended)" $?
[ "$(remote_file "$B" | grep -cE "code_hash *= *\"$H\"")" = "1" ]
check "the entry still appears exactly once" $?
run_record "$B/work" --verify-only
check "and --verify-only agrees with it" "$STATUS"

# --- 15. Wrong repository -------------------------------------------------

case_start "remote points at a fork: refuses before touching the network"
B=$(fixture fork)
git -C "$B/work" remote set-url origin "https://github.com/notfreenet/ghostkeys.git"
run_record "$B/work"
[ "$STATUS" -ne 0 ]
check "exits non-zero" $?
echo "$OUT" | grep -q "notfreenet/ghostkeys"
check "names the repository it was pointed at" $?
echo "$OUT" | grep -q "freenet/ghostkeys"
check "names the one it expected" $?
echo "$OUT" | grep -q "Recording there would protect nobody"
check "explains why that is not merely untidy" $?

case_start "malformed retry count is rejected, not looped on"
B=$(fixture badattempts)
OUT="$(cd "$B/work" && GHOSTKEYS_RECORD_REMOTE=origin GHOSTKEYS_RECORD_BRANCH=main \
    GHOSTKEYS_RECORD_PUSH_ATTEMPTS=abc timeout 20 bash scripts/record-migration.sh 2>&1)"
STATUS=$?
[ "$STATUS" -eq 2 ]
check "exits 2 immediately (a non-numeric count used to spin forever)" $?

# --- 16. The publish ordering is load-bearing; pin it ---------------------
#
# Recording after `fdev network publish` is the state this whole change moved
# away from, and nothing else in this suite would notice it moving back: every
# case above drives the script, not the task that sequences it.

case_start "Makefile keeps record-then-publish-then-verify in that order"
MK="$REPO_ROOT/Makefile.toml"
REC_LINE=$(grep -n 'bash scripts/record-migration.sh$' "$MK" | head -1 | cut -d: -f1)
PUB_LINE=$(grep -n 'fdev network publish' "$MK" | head -1 | cut -d: -f1)
VER_LINE=$(grep -n 'bash scripts/record-migration.sh --verify-only' "$MK" | head -1 | cut -d: -f1)
[ -n "$REC_LINE" ] && [ -n "$PUB_LINE" ] && [ -n "$VER_LINE" ]
check "all three steps are present in publish-ghostkeys" $?
[ "${REC_LINE:-0}" -lt "${PUB_LINE:-0}" ]
check "the record is written BEFORE the publish (nothing goes live unrecorded)" $?
[ "${PUB_LINE:-0}" -lt "${VER_LINE:-0}" ]
check "the re-verify runs AFTER the publish" $?
grep -q 'preflight-migration' "$MK"
check "sign-webapp still depends on preflight-migration" $?

# --- Summary --------------------------------------------------------------

echo ""
echo "-------------------------------------------"
echo "passed: $PASS   failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
    echo "RECORD-MIGRATION TESTS FAILED" >&2
    exit 1
fi
echo "all record-migration tests passed"
