# FREENET.md

This file enumerates the Freenet contracts and delegates published from this repository — what each one is for, where its source lives, and how to depend on it — for anyone integrating with ghostkeys rather than building it. It's a convention (see [freenet-core#5194](https://github.com/freenet/freenet-core/issues/5194)), not a protocol requirement: a fixed, predictable place to look before reading source.

## Delegates

### ghostkey-delegate
- **Purpose:** Holds a user's ghost key identities (anonymous, blind-signed cryptographic certificates) and signs on their behalf, with explicit per-request consent. This is a **platform service** — any other Freenet app (chat, forum, marketplace) can request a signature through it without ever touching the private key.
- **Source:** [`delegates/ghostkey-delegate/`](delegates/ghostkey-delegate/)
- **Shared types crate:** [`ghostkey-common`](common/) — not yet published to crates.io; depend via a git or path dependency for now.
- **Migration:** re-keys on any WASM change, including a bare version bump (verified: 0.2.3 → 0.2.4 with no functional change re-keyed the delegate). `legacy_delegates.toml` records every prior generation, and the vault UI sweeps it on load to carry a user's existing ghost keys forward automatically — see the design notes in [`.claude/rules/delegate-migration.md`](.claude/rules/delegate-migration.md).
- **Third-party integrators do not get this migration for free.** A build-time-constant reference to a delegate key silently addresses a stale namespace after a re-key — this is the exact failure that motivated [freenet-core#5194](https://github.com/freenet/freenet-core/issues/5194) and [ghostkeys#22](https://github.com/freenet/ghostkeys/pull/22)'s `delegate-key.json` stopgap (`published-contract/`, written into the signed webapp bundle so a fresh vault load always names the current key).

## Contracts

ghostkeys does not maintain its own contract source. The vault UI is served via the generic, reusable `web-container-contract` WASM (the same one River publishes) — see `published-contract/web_container_contract.wasm`, currently deployed at `DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N`. Reusing the compiled artifact directly, rather than vendoring the source, is the intended pattern for any app that just needs to serve a signed webapp bundle.

## Notes for integrators

- There is no stable-identity pointer published yet for the delegate; track [freenet-core#5194](https://github.com/freenet/freenet-core/issues/5194) for when one lands, and `delegate-key.json` in the meantime.
- Permission scopes matter: a third-party app requesting signatures gets a restricted scope set (`ReadPublic`, `Sign`), never `Export`/`Delete`/`Admin` — see `delegates/ghostkey-delegate/src/permissions.rs`.
