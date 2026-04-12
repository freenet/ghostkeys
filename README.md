# Ghostkeys

A Freenet [delegate](https://freenet.org/resources/manual/components/delegates/) for managing [ghost key](https://freenet.org/ghostkey/) identities -- cryptographic certificates that prove trust without revealing identity.

Ghost keys solve a fundamental internet problem: how do you verify someone is trustworthy without knowing who they are? Through a blind signing protocol, users receive a cryptographic certificate signed by Freenet's server that can never be linked back to them. This enables spam prevention, bot blocking, and trust verification while preserving complete anonymity.

This delegate is a platform service. Any application running on Freenet -- a chat app, a forum, a marketplace -- can request signatures from the ghostkeys delegate on behalf of the user, with the user's explicit permission. The application never touches the private key; it just gets back a verifiable signature proving the user holds a legitimate ghost key.

For background, see [the introductory article](https://freenet.org/news/introducing-ghost-keys/) or [watch the interview with Ian Clarke](https://freenet.org/news/ghost-keys-ian-interview/).

## Why a delegate?

On Freenet, [delegates](https://freenet.org/resources/manual/components/delegates/) are software agents that run on the user's machine and hold secrets on their behalf. Unlike traditional software encapsulation (which is just convention), delegates enforce real isolation at the platform level: the private state inside a delegate is not directly accessible to anything else. The only way to interact with a delegate is through its message interface, and the delegate can apply policy to every request.

Freenet's runtime attests the identity of every caller -- when the ghostkeys delegate receives a request, it knows exactly which application or delegate sent it, and this identity can't be spoofed. This is what makes the permission and scoping systems described below possible.

This matters because ghost keys contain private signing keys. If those keys were held by the application itself, any app could sign anything, impersonate users, or leak keys. By placing them in a delegate, the keys stay in one secure place and applications request signatures through a controlled interface with user consent.

## How ghost keys are created

1. User makes a donation to Freenet
2. Browser generates an [Ed25519](https://en.wikipedia.org/wiki/EdDSA) key pair
3. The public key is [blinded](https://www.rfc-editor.org/rfc/rfc9474.html) and sent to the server
4. Server verifies the donation, signs the blinded key with its RSA key, and returns it
5. Browser unblinds the signature and combines it into a certificate
6. The certificate proves the donation was made without revealing who made it

The certificate also records the donation amount and date, so applications can make trust decisions based on how much someone invested and when -- without knowing who they are.

## Integrating with ghostkeys

If you're building a Freenet application and want to verify users or prevent spam, you interact with the ghostkeys delegate through Freenet's delegate messaging API. Your app sends a `GhostkeyRequest`, the user is prompted for permission, and you receive a `GhostkeyResponse`.

### Requesting a signature

Your application sends a `SignMessage` request specifying which ghost key to use (by fingerprint) and the message to sign:

```rust
use ghostkey_common::{GhostkeyRequest, to_cbor};

let request = GhostkeyRequest::SignMessage {
    fingerprint: "abc123".into(),
    message: b"hello world".to_vec(),
};

// Send via Freenet's delegate messaging API
let payload = to_cbor(&request).unwrap();
// ... send as DelegateMessage or ApplicationMessage to the ghostkeys delegate
```

The delegate checks whether your application has permission. If this is the first time your app has requested access to this key, the user sees a prompt in their browser:

> "Web app DLog47h... wants to access ghostkey abc123. Allow?"

The user can choose **allow once**, **always allow**, or **deny**. If they choose "allow once", the permission is automatically revoked after the request completes.

On approval, the delegate signs the message and returns a `SignResult`:

```rust
use ghostkey_common::GhostkeyResponse;

// The response you receive:
GhostkeyResponse::SignResult {
    scoped_payload,   // CBOR-serialized ScopedPayload (message + caller identity)
    signature,        // Ed25519 signature over scoped_payload
    certificate_pem,  // Full certificate chain for verification
}
```

### Verifying a signature

Any party can verify a signature -- they don't need access to the delegate. Given the signed bundle, verification checks the Ed25519 signature, validates the certificate chain back to Freenet's master key, and extracts the original message along with metadata:

```rust
let request = GhostkeyRequest::VerifySignedMessage {
    signed_message: bundle_bytes,
};

// Response:
GhostkeyResponse::VerifyResult {
    valid: true,
    signer_fingerprint: Some("abc123".into()),
    delegate_info: Some("{\"action\":\"freenet-donation\",\"amount\":20,...}".into()),
    requestor: Some(SignatureRequestor::WebApp(contract_id)),
    message: Some(original_message_bytes),
}
```

The `delegate_info` field contains the donation tier, so a verifier can see "this was signed by someone who donated $20" without learning anything about who that person is.

### Scoped signatures

The delegate never signs raw messages. Every signature wraps the message in a `ScopedPayload` that includes the runtime-attested identity of the requesting application:

```rust
pub struct ScopedPayload {
    pub requestor: SignatureRequestor,  // Which app/delegate requested this
    pub payload: Vec<u8>,              // The actual message
}
```

This is a deliberate design choice. If App A obtains a signature, that signature includes App A's identity in the signed data. App B cannot strip that out and claim the signature was made for it -- the signature verification would fail. This prevents signature harvesting: a malicious app can't collect signatures and replay them in a different context.

The `SignatureRequestor` is attested by Freenet's runtime, not self-reported by the caller:

```rust
pub enum SignatureRequestor {
    WebApp(ContractInstanceId),  // A web app, identified by its contract
    Delegate(DelegateKey),       // Another delegate on the same node
}
```

### Permission model in practice

Not all operations require permission. Importing a key and listing keys are open; the sensitive operations -- signing, exporting, reading certificate details, deleting -- require explicit user consent.

The flow when an unpermitted app makes a request:

1. App sends `SignMessage` to the ghostkeys delegate
2. Delegate checks permissions, finds none for this app + key combination
3. Delegate stores the pending request and emits a `RequestUserInput` prompt
4. User sees the prompt in their browser with three options: allow / always allow / deny
5. On approval, the delegate replays the original request with permission now granted
6. If "allow once" was chosen, the permission is revoked immediately after the response is sent

This means your application doesn't need to handle the permission flow at all -- it just sends the request and eventually gets back either a `SignResult` or a `PermissionDenied`. The delegate and Freenet's runtime handle the user interaction transparently.

## Architecture

This is a Rust workspace with three crates:

- **`common/`** -- Shared types and CBOR serialization for the request/response protocol between delegate and UI
- **`delegates/ghostkey-delegate/`** -- The Freenet delegate (compiles to WASM) that stores signing keys and handles identity operations
- **`ui/`** -- Dioxus web frontend for managing identities, signing messages, and granting permissions

### Certificate chain

```
Master Key -> Notary Certificate -> Ghost Key Certificate
```

Each ghost key is identified by a fingerprint (first 8 bytes of BLAKE3 hash of the verifying key, base58-encoded).

### Operations

| Request | Description |
|---------|-------------|
| `ImportGhostKey` | Store a new ghost key from PEM certificate + signing key |
| `ListGhostKeys` | List ghost keys the caller has access to |
| `GetGhostKey` | Get full certificate details for a key |
| `GetCertificate` | Get just the public certificate (for sharing) |
| `SignMessage` | Sign a message with a ghost key (scoped to caller) |
| `VerifySignedMessage` | Verify a signed message and extract metadata |
| `ExportGhostKey` | Export certificate + private signing key for backup |
| `DeleteGhostKey` | Remove a stored ghost key |
| `SetLabel` | Set a user-friendly name for a key |
| `GrantPermission` | Grant another app/delegate access to a key |
| `RevokePermission` | Revoke access |
| `ListPermissions` | List who has access to a key |

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
