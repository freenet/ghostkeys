# Delegate WASM Migration Required

Changes to these paths can alter the delegate WASM hash, which changes the delegate key.
Without a migration entry, **users lose all stored ghostkeys**.

## Paths that affect delegate WASM

- `delegates/ghostkey-delegate/src/`
- `common/src/`
- `Cargo.toml` (dependency version changes)
- `Cargo.lock` (transitive dependency changes)

## How the safeguards work

The publish pipeline has two automatic checks that make it hard to lose user
data:

1. **`cargo make check-migration`** runs automatically before
   `publish-ghostkeys` signs the webapp, and on every PR that touches a path
   above. It verifies two things:

   - every recorded entry is internally consistent (`delegate_key` really is
     BLAKE3 over the raw bytes of `code_hash`), so a hand-edited entry cannot
     silently point the sweep at a delegate that never existed;
   - **no previously-recorded entry has been dropped.** That is the property
     that actually protects users: the vault only sweeps delegates listed in
     `legacy_delegates.toml`, so removing the entry a user is running makes
     their ghostkeys unreachable with no error shown.

2. **`cargo make record-migration`** runs automatically as part of
   `publish-ghostkeys`, *before* the publish itself. It records the hash about
   to be deployed as the new baseline, so the *next* delegate change is
   covered even if nobody runs `add-migration`.

   It writes to **`origin/main`, not to your checkout**: it builds the commit
   on top of the fetched tip of main and pushes it there, then re-reads the
   file off the remote to confirm it landed. Your branch, HEAD, index and
   working tree are not touched (beyond a fast-forward of a clean local
   `main`, as a convenience).

   That is deliberate. Recording into the local checkout leaves the record one
   forgotten `git push` — or one abandoned PR — away from not existing, which
   is exactly the 2026-08-03 failure (ghostkeys#29, and see the `Historical
   gotcha` below). No CI check can catch that state, because a record that
   never left a laptop produces no event for CI to inspect.

   **If it cannot land the record, it fails and the publish aborts** with
   nothing deployed. Fix whatever it reports (usually connectivity, or main
   having moved) and re-run; it is idempotent, so an already-recorded hash is
   a no-op. If `main` is ever branch-protected, it prints the exact entry to
   put in a PR, and the publish will sail past that step once the PR merges.

### What the check deliberately does NOT require

It does not require the newly-built WASM hash to be in `legacy_delegates.toml`.

It used to, and that was backwards (ghostkeys#10). A PR cannot record its own
post-publish hash, because it has not published yet — and the CI runner's WASM
bytes differ from a local build anyway (ghostkeys#9), so whatever you recorded
pre-publish would not even be the hash CI computes. The guard failed precisely
when you followed the documented order, which is the kind of check people learn
to route around.

The successor's hash is knowable only at publish time, and `record-migration`
records it there.

## Before making changes (optional)

```bash
cargo make add-migration
```

This records the *current* (pre-change) delegate key. It is normally a no-op,
because `record-migration` already recorded that hash on `main` when it was
published. It is worth running if you are hand-publishing via `fdev` or
debugging the migration flow — anything that bypassed the task graph and so
may have skipped the automatic recording.

Unlike `record-migration`, this one writes to your **working tree** and stops
there. Commit it with the PR that makes the change; until you do,
`check-migration` will refuse to publish, because an entry that exists only in
your checkout protects nobody.

## Publishing changes

```bash
cargo make publish-ghostkeys
```

This builds the delegate, runs `preflight-migration`, builds the UI,
compresses and signs the webapp, runs `check-migration`, records the hash on
`origin/main` via `record-migration`, publishes to Freenet, and then re-reads
the record off the remote to confirm it is still there.

**There is no follow-up step for the record.** It reaches `origin/main` before
anything is published, or the publish does not happen. (Your *checkout* may
still need a `git pull` afterwards, and if you published from a branch you
will want to merge or rebase onto `main` before opening a PR from it.)

### Publish from an up-to-date checkout

`preflight-migration` refuses to publish when your `legacy_delegates.toml` is
missing entries that `origin/main` already has, and it runs before the UI is
built so you find out early.

That is not bookkeeping. `ui/build.rs` compiles `legacy_delegates.toml` **from
your working tree** into the webapp bundle, so the sweep table users actually
get is the one in your checkout — not the one on `main`. A checkout that is
merely *behind* would otherwise ship a table missing entries `main` has, and
orphan everyone running those delegates. `check-migration` cannot catch it: it
compares against the merge base, where those entries do not exist yet.

If it fires: `git pull --ff-only` on `main` (or merge `main` into your branch),
then re-run the publish so the bundle is rebuilt from the complete table.

Verify the WASM hash changed:
```bash
b3sum --no-names target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm
```

If it matches the previous-last entry in `legacy_delegates.toml`, the change
didn't affect the WASM (e.g. UI-only change) and no migration entry was
needed — `record-migration` is a no-op in that case.

## Historical gotcha

**Do not skip the Makefile task.** Running `fdev network publish` directly
bypasses both safeguards. An earlier incident (2026-04) almost shipped a
delegate change without recording the previous deployed hash because the
author had hand-built the WASM outside the task graph.

## Key formula

`delegate_key = BLAKE3(BLAKE3(wasm) || params)` -- both steps use BLAKE3.
Scripts assume empty params.
