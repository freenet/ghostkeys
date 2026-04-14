# Delegate WASM Migration Required

Changes to these paths can alter the delegate WASM hash, which changes the delegate key.
Without a migration entry, **users lose all stored ghostkeys**.

## Paths that affect delegate WASM

- `delegates/ghostkey-delegate/src/`
- `common/src/`
- `Cargo.toml` (dependency version changes)
- `Cargo.lock` (transitive dependency changes)

## How the safeguards work

The publish pipeline now has two automatic checks that make it hard to lose
user data:

1. **`cargo make check-migration`** runs automatically before `publish-ghostkeys`
   signs the webapp. It hashes the just-built delegate WASM and verifies the
   legacy_delegates.toml chain. It fails fast if the built hash is neither a
   no-op (already recorded) nor a valid forward-migration target.

2. **`cargo make record-migration`** runs automatically after a successful
   publish. It appends the just-deployed hash to `legacy_delegates.toml` as
   the new baseline, so the *next* delegate change is automatically covered
   even if nobody remembers to run `add-migration` manually.

The combined effect: as long as you run `cargo make publish-ghostkeys`
through the proper task (not a bare `fdev network publish`), every
deployment is recorded and the next one has migration coverage without
requiring conscious action.

## Before making changes (legacy manual flow)

```bash
cargo make add-migration
```

This records the current delegate key in `legacy_delegates.toml`. With the
new safeguards this is only necessary if you're doing something unusual
(e.g. hand-publishing via `fdev` or debugging migration flow). Normal
publish cycles via `cargo make publish-ghostkeys` handle recording
automatically.

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
