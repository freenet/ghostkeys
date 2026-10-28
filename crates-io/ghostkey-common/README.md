# ghostkey-common

Wire types for communicating with the Freenet **ghostkey delegate**.

Use this crate from a Freenet dapp that needs to ask the user to sign
messages, enumerate their ghostkey identities, or verify signed messages
produced by the delegate. It contains only the request/response enums
(`GhostkeyRequest`, `GhostkeyResponse`) and supporting types — no I/O,
no delegate implementation, no crypto primitives beyond optional
fingerprint computation behind the `crypto` feature.

## Layering

Three ghostkey-prefixed crates exist on crates.io; they serve different layers:

| Crate | Layer | Use when |
|---|---|---|
| [`ghostkey_lib`](https://crates.io/crates/ghostkey_lib) | Low-level crypto | You need to mint, sign, or verify ghostkey certificates directly (usually only the notary server and the delegate itself). |
| [`ghostkey-common`](https://crates.io/crates/ghostkey-common) | Delegate wire types | You are writing a Freenet dapp that talks to the ghostkey delegate running on the user's node. **This is what dapps want.** |
| [`ghostkey`](https://crates.io/crates/ghostkey) | CLI | You want a command-line tool for ghostkey operations. |

## Features

- `crypto` (off by default): enables fingerprint computation via
  `ed25519-dalek`, `blake3`, and `bs58`. The delegate turns this on;
  most dapps won't need it.

## freenet-stdlib versions

The wire types embed freenet-stdlib's `ContractInstanceId` and `DelegateKey`,
and everything linked into one WASM must share a single freenet-stdlib. From
0.4.0 this crate accepts any freenet-stdlib from 0.8 up to (not including)
0.13; those types encode identically across that range. The crate's tests pin
the bytes, and the ghostkeys repository's CI runs them at both ends of the
range and at its newest release.

On 0.12, nothing to do. On an older stdlib, a fresh resolve or a
`cargo update` picks the range's newest version rather than yours (adding
0.4 to a lockfile that already has your stdlib reuses it). That usually shows
up as a `mismatched types` error naming two freenet-stdlib versions; if no
stdlib type crosses between your code and this crate, it builds quietly with
both linked. In the crate that owns the `Cargo.lock` (your application), point
it back at yours:

```sh
cargo update -p freenet-stdlib@0.12 --precise 0.8.5   # your version here
```

A plain `cargo update` undoes this, so redo it after one. A library can't do
it for its own users at all. If you are on freenet-stdlib 0.8.x, the simplest
option is to stay on ghostkey-common 0.3 (which requires `^0.8`): its wire
types are identical. On 0.9 to 0.11 there is no 0.3 option; pin as above.

## License

MIT OR Apache-2.0
