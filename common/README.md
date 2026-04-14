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

## License

MIT OR Apache-2.0
