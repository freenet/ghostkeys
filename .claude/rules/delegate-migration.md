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

2. **`cargo make record-migration`** runs automatically after a successful
   publish. It appends the just-deployed hash as the new baseline, so the
   *next* delegate change is covered even if nobody runs `add-migration`.

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
because `record-migration` already recorded that hash right after it was
published. It is worth running if you are hand-publishing via `fdev` or
debugging the migration flow — anything that bypassed the task graph and so
may have skipped the automatic recording.

## Publishing changes

```bash
cargo make publish-ghostkeys
```

This builds the delegate, runs `check-migration`, builds the UI, compresses
and signs the webapp, publishes to Freenet, and then runs `record-migration`
to append the deployed hash to `legacy_delegates.toml`.

**After the publish completes, commit and push `legacy_delegates.toml`**
so other machines / future sessions see the updated baseline.

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
