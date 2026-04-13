# Delegate WASM Migration Required

Changes to these paths can alter the delegate WASM hash, which changes the delegate key.
Without a migration entry, **users lose all stored ghostkeys**.

## Paths that affect delegate WASM

- `delegates/ghostkey-delegate/src/`
- `common/src/`
- `Cargo.toml` (dependency version changes)
- `Cargo.lock` (transitive dependency changes)

## Before making changes

```bash
cargo make add-migration
```

This records the current delegate key in `legacy_delegates.toml`. The migration
system will then read from the old delegate and re-import keys into the new one.

## After making changes

```bash
cargo make publish-ghostkeys
```

Verify the WASM hash changed:
```bash
b3sum --no-names target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm
```

If it matches the last entry in `legacy_delegates.toml`, the change didn't affect the WASM
(e.g. UI-only change) and no migration entry was needed.

## Key formula

`delegate_key = BLAKE3(BLAKE3(wasm) || params)` -- both steps use BLAKE3.
