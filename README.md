# Ghostkeys

A Freenet delegate for managing [ghost key](https://freenet.org/ghostkey/) identities -- cryptographic certificates that prove trust without revealing identity.

Ghost keys solve a fundamental internet problem: how do you verify someone is trustworthy without knowing who they are? Through a blind signing protocol, users receive a cryptographic certificate signed by Freenet's server that can never be linked back to them. This enables spam prevention, bot blocking, and trust verification while preserving complete anonymity.

For background, see [the introductory article](https://freenet.org/news/introducing-ghost-keys/) or [watch the interview with Ian Clarke](https://freenet.org/news/ghost-keys-ian-interview/).

## How it works

1. User makes a donation to Freenet
2. Browser generates an [Ed25519](https://en.wikipedia.org/wiki/EdDSA) key pair
3. The public key is [blinded](https://www.rfc-editor.org/rfc/rfc9474.html) and sent to the server
4. Server verifies the donation, signs the blinded key with its RSA key, and returns it
5. Browser unblinds the signature and combines it into a certificate
6. The certificate proves the donation was made without revealing who made it

## Architecture

This is a Rust workspace with three crates:

- **`common/`** -- Shared types and CBOR serialization for the request/response protocol between delegate and UI
- **`delegates/ghostkey-delegate/`** -- The Freenet delegate (compiles to WASM) that stores signing keys and handles identity operations
- **`ui/`** -- Dioxus web frontend for managing identities, signing messages, and granting permissions

### Certificate chain

```
Master Key -> Delegate Certificate -> Ghost Key Certificate
```

Each ghost key is identified by a fingerprint (first 8 bytes of BLAKE3 hash of the verifying key, base58-encoded).

### Operations

The delegate supports: importing keys, listing/exporting keys, signing and verifying messages, and managing per-app permissions. Signatures are scoped -- they include the identity of the requesting application, preventing signature reuse across contexts.

### Permission model

Applications on Freenet request access to ghost keys through the delegate. Users are prompted to allow once, always allow, or deny. This ensures signing keys never leave the delegate.

### Delegate UI

When running a Freenet peer locally, the ghost key management UI is available at:

```
http://127.0.0.1:7509/v1/contract/web/DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N/
```

## Building

Requires [cargo-make](https://github.com/sagiegurari/cargo-make):

```bash
cargo install cargo-make
```

Build the delegate (WASM):
```bash
cargo make build-delegate
```

Build the UI:
```bash
cargo make build-ui
```

Run the dev server with hot reload:
```bash
cargo make dev
```

Run tests:
```bash
cargo make test
```

## Ghost Key CLI

A separate [command-line tool](https://crates.io/crates/ghostkey) is available for generating, verifying, and using ghost keys outside of Freenet:

```
cargo install ghostkey
ghostkey -h
```

The CLI is part of the [freenet/web](https://github.com/freenet/web) repository (`rust/cli/`).

## Dependencies

| Crate | Purpose |
|-------|---------|
| [freenet-stdlib](https://crates.io/crates/freenet-stdlib) | Delegate framework and WebSocket API |
| [ghostkey_lib](https://crates.io/crates/ghostkey_lib) | Certificate and signing key serialization |
| [ed25519-dalek](https://crates.io/crates/ed25519-dalek) | Ed25519 signing and verification |
| [dioxus](https://dioxuslabs.com/) | Web UI framework (WASM target) |
| [ciborium](https://crates.io/crates/ciborium) | CBOR wire protocol encoding |
| [blake3](https://crates.io/crates/blake3) | Key fingerprinting |

## License

MIT OR Apache-2.0
