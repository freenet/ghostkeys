# FREENET.md

This file enumerates the Freenet contracts and delegates published from this repository — what each one is for, where its source lives, and how to depend on it — for anyone integrating with ghostkeys rather than building it. It's a convention (see [freenet-core#5194](https://github.com/freenet/freenet-core/issues/5194)), not a protocol requirement: a fixed, predictable place to look before reading source.

## Delegates

### ghostkey-delegate
- **Purpose:** Holds a user's ghost key identities (anonymous, blind-signed cryptographic certificates) and signs on their behalf, with explicit per-request consent. This is a **platform service** — any other Freenet app (chat, forum, marketplace) can request a signature through it without ever touching the private key.
- **Source:** [`delegates/ghostkey-delegate/`](delegates/ghostkey-delegate/)
- **Shared types crate:** [`ghostkey-common`](common/) — not yet published to crates.io; depend via a git or path dependency for now.
- **Migration:** re-keys on any WASM change, including a bare version bump (verified: 0.2.3 → 0.2.4 with no functional change re-keyed the delegate). `legacy_delegates.toml` records every prior generation, and the vault UI sweeps it on load to carry a user's existing ghost keys forward automatically — see the design notes in [`.claude/rules/delegate-migration.md`](.claude/rules/delegate-migration.md).
- **Addressing it from another app:** resolve the pointer below. A build-time-constant delegate key silently addresses an empty namespace after a re-key — the failure reported in [ghostkeys#21](https://github.com/freenet/ghostkeys/issues/21).

## Contracts

ghostkeys does not maintain its own contract source. The vault UI is served via the generic, reusable `web-container-contract` WASM (the same one River publishes) — see `published-contract/web_container_contract.wasm`, currently deployed at `DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N`. Reusing the compiled artifact directly, rather than vendoring the source, is the intended pattern for any app that just needs to serve a signed webapp bundle.

## Notes for integrators

- The delegate re-keys on any release — **a build-time-constant reference to its key will silently go stale.** Resolve a pointer instead; see below.
- Permission scopes matter: a third-party app requesting signatures gets a restricted scope set (`ReadPublic`, `Sign`), never `Export`/`Delete`/`Admin` — see `delegates/ghostkey-delegate/src/permissions.rs`.

## Stable identity: resolve a pointer, do not pin a key

ghostkeys publishes a **pointer record** for the delegate. A pointer record is a contract at a **fixed address** whose state names the artifact's *current* code hash, signed by ghostkeys' author key. You GET the pointer, read the code hash, and derive the key you actually wanted from that hash **plus your own params** (the delegate takes empty params, so its key is simply `BLAKE3(code_hash_bytes)`). The address never changes, so your build-time constant never goes stale.

This implements the convention in [freenet-core#5194](https://github.com/freenet/freenet-core/issues/5194), and it is the durable answer to [ghostkeys#21](https://github.com/freenet/ghostkeys/issues/21).

### The author verifying key — your trust anchor

```
river:v1:vk:6kWWDBPRne385neUxXmzqpabUYxRbBYCTYSS8BAcPb29
```

Pin **this 32-byte value** as a constant in your build, and take it **from this file** — not from a third-party table, a blog post, or a copy in someone else's SDK. It is the entire trust anchor: take it from anywhere else and you may resolve a validly-signed pointer belonging to somebody else, with no error anywhere to tell you.

You can check it without trusting this file — its raw bytes are `published-contract/webapp.parameters`, which is why the vault's web container id `DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N` derives from it. (The `river:v1:vk:` prefix is just the shared encoding ghostkeys reuses from River's `web-container-tool`; it says nothing about ownership.)

Two things we would rather you learned here than discovered later:

- **ghostkeys does not keep this key offline.** It is the same key used on every vault publish. ghostkeys has no separate author identity — ghost keys are per-*user* blind-signed certificates, so this is the only publisher identity it has.
- **Rotating it would move everything at once** — the vault's web container address and the pointer address. That would strand anyone who baked in the author vk, so it is a coordinated flag day, not routine key hygiene.

### The pointer

| `app_id` | Points at | Pointer key (fixed, GET this) |
|---|---|---|
| `ghostkeys.ghostkey-delegate` | [`delegates/ghostkey-delegate/`](delegates/ghostkey-delegate/) | `HYBCmCSGKjr4jUUoTzivZ48UynjLscwA3nvnpKQAwi3a` |

That address is derivable offline from the pointer contract's frozen code hash `8wnAPaSRY1oYZCz723fdwK6BgzL6q8ozP3buVovXnt6v` and `(author_vk ‖ app_id)` — you do not have to trust the table.

The current record is in [`pointer-records.toml`](pointer-records.toml), which CI checks on every PR (`scripts/check-pointer-freshness.sh`): if the delegate WASM changes and no new record is signed, the build fails. That gate is the reason resolving is safer than pinning.

### How to resolve

Rust integrators should use the resolver rather than hand-rolling it — it carries the anti-rollback floor and the absence-vs-unreachability distinction, neither of which you get from decoding the record yourself:

```rust
use freenet_migrate::pointer::{resolve_app_pointer, PointerFloor, PointerOutcome};

let outcome = resolve_app_pointer(&mut io, &GHOSTKEYS_AUTHOR_VK, b"ghostkeys.ghostkey-delegate", floor).await?;
```

Handle **every** arm. A bare `if let Some(r) = outcome.resolved()` silently does nothing on the outcomes that carry no record, which is how a withdrawal, a rollback attempt and a plain timeout all become "no output". Only `NeverPublished` permits falling back to a baked-in key. Persist `outcome.next_floor()`, keyed by `(author_vk, app_id)`.

Non-Rust implementers: the wire format, the four resolution steps and hex test vectors are in the [pointer contract's README](https://github.com/freenet/freenet-migrate/tree/main/contracts/pointer-contract).

### `delegate-key.json` — the fallback, still supported

Before the pointer existed, ghostkeys published the delegate key as a file inside the signed vault webapp bundle ([ghostkeys#22](https://github.com/freenet/ghostkeys/pull/22)), fetchable at:

```
/v1/contract/web/DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N/delegate-key.json
```

It is served with `Access-Control-Allow-Origin: *` and works from a sandboxed frame. It carries `delegate_key` and `code_hash` as both hex and `number[]`, and it is written into the bundle at publish time by `scripts/write-delegate-pointer.sh`, so it cannot drift from the delegate it names.

**This is not deprecated and is not going away.** The two paths coexist, and the same publish gate (`scripts/check-delegate-pointer.sh`) checks both against the delegate actually being shipped, so they cannot disagree. Which to use:

- **Prefer the pointer** if you can GET a contract. It is signed by an identity you pin yourself, it does not depend on the vault's web container remaining at its current address, and it resolves without fetching and parsing a webapp bundle.
- **`delegate-key.json` is fine** if you are a browser app already talking to a gateway over HTTP and adding a contract GET is disproportionate. You are trusting the web container's address instead of the author key — a weaker anchor, but one you already trust if you link users to the vault.

### What a pointer does NOT tell you

**It solves addressing only.** It tells you which code hash is current. It says nothing about whether any state or any secret held under the previous key survived the re-key.

For ghostkeys that gap is the expensive one, because the secrets are keys users **paid for**. Ghost keys move forward only when the ghostkeys vault UI has run on that user's node and swept `legacy_delegates.toml`. So you can resolve this pointer perfectly, derive exactly the right delegate key, and still find an **empty namespace** — which looks like "this user has no ghost key" rather than like an error, and which is how a user who already bought one gets told to go and buy another. That is precisely the [ghostkeys#21](https://github.com/freenet/ghostkeys/issues/21) report.

So please do not let that confusion back in one level up: treat data survival as a separate question from addressing, assume it is unsolved until you have verified it, and when you find an empty namespace say "could not find your ghost key" rather than "you do not have one".
