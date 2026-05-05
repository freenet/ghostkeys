use freenet_stdlib::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "crypto")]
use ed25519_dalek::VerifyingKey;

/// Compute fingerprint for a ghostkey verifying key.
/// First 8 bytes of BLAKE3(verifying_key_bytes), base58-encoded.
#[cfg(feature = "crypto")]
pub fn fingerprint(verifying_key: &VerifyingKey) -> String {
    let hash = blake3::hash(verifying_key.as_bytes());
    bs58::encode(&hash.as_bytes()[..8]).into_string()
}

/// Serialize a value to CBOR bytes.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| format!("CBOR serialize: {e}"))?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes.
pub fn from_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| format!("CBOR deserialize: {e}"))
}

/// Who requested a ghostkey operation. Runtime-attested, can't be spoofed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureRequestor {
    /// A web application (UI) backed by this contract.
    WebApp(ContractInstanceId),
    /// Another delegate on the same node.
    Delegate(DelegateKey),
}

/// What an authorised caller is allowed to do with a ghostkey.
///
/// A grant carries a set of scopes. The vault auto-grants itself every
/// scope when it imports a key. Third-party apps can request access via
/// `RequestAnyAccess`, which (on user approval) grants only
/// `{ReadPublic, Sign}` -- enough to read the public certificate and sign
/// messages, but not enough to extract the private key or destroy the
/// identity. Apps that need higher privileges are deliberately routed
/// through the vault, where the user is rendering the management UI.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum GhostkeyScope {
    /// Read public certificate and metadata. Granted alongside `Sign`
    /// because every signing UI also wants to display the public cert.
    ReadPublic,
    /// Sign messages with the private key. Implies `ReadPublic` in
    /// practice (a verifier needs the cert), but gating is per-scope so
    /// the grant intent is explicit.
    Sign,
    /// Export the private signing key. Catastrophic if granted to a
    /// third-party app -- the recipient becomes able to sign as the
    /// user offline. Only ever granted to the vault.
    Export,
    /// Delete the ghostkey or rewrite its label. Only ever granted to
    /// the vault.
    Delete,
    /// Manage permissions for this ghostkey: grant/revoke other apps'
    /// access. The vault gets this on import; third-party apps never
    /// get it via `RequestAnyAccess`.
    Admin,
}

/// What the ghostkey delegate actually signs. The raw payload is never signed
/// alone -- always wrapped with the attested caller identity.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScopedPayload {
    pub requestor: SignatureRequestor,
    pub payload: Vec<u8>,
}

/// Summary info about a stored ghostkey.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GhostKeyInfo {
    pub fingerprint: String,
    pub label: Option<String>,
    /// The notary certificate info field (encodes donation tier).
    /// Historically called `delegate_info` — the wire-format key is frozen
    /// via `#[serde(rename)]` for backward compat with stored state.
    /// See freenet/web#24.
    #[serde(rename = "delegate_info")]
    pub notary_info: String,
    /// Ed25519 verifying key bytes (32 bytes). Added in 0.2.2 for dapps
    /// that need the raw key (e.g. Harvest store contract parameters).
    #[serde(default)]
    pub verifying_key_bytes: Option<Vec<u8>>,
}

/// A ghostkey exported for backup (includes private signing key).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExportedGhostKey {
    pub fingerprint: String,
    pub certificate_pem: String,
    pub signing_key_pem: String,
    pub label: Option<String>,
    #[serde(rename = "delegate_info")]
    pub notary_info: String,
}

/// Requests from UI or other delegates to the ghostkey delegate.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[non_exhaustive]
pub enum GhostkeyRequest {
    /// Import a ghostkey from PEM-armored certificate and signing key.
    /// If master_verifying_key_pem is None, uses the hardcoded Freenet master key.
    ImportGhostKey {
        certificate_pem: String,
        signing_key_pem: String,
        #[serde(default)]
        master_verifying_key_pem: Option<String>,
    },
    /// List all stored ghostkeys.
    ListGhostKeys,
    /// Get details for a specific ghostkey.
    GetGhostKey { fingerprint: String },
    /// Get just the public certificate (for sharing with counterparties).
    GetCertificate { fingerprint: String },
    /// Delete a stored ghostkey.
    DeleteGhostKey { fingerprint: String },
    /// Set a user-friendly label.
    SetLabel { fingerprint: String, label: String },
    /// Sign a message with a specific ghostkey. The delegate scopes the
    /// signature to the requestor.
    SignMessage {
        fingerprint: String,
        message: Vec<u8>,
    },
    /// Sign a message with the user's default ghostkey (highest-tier key,
    /// or user-overridden via SetDefaultKey). Apps should prefer this over
    /// SignMessage -- it avoids needing to know about specific fingerprints.
    SignWithDefault { message: Vec<u8> },
    /// Set which ghostkey is the default for signing.
    SetDefaultKey { fingerprint: String },
    /// Get the current default ghostkey fingerprint.
    GetDefaultKey,
    /// Verify a signed message produced by this delegate.
    VerifySignedMessage { signed_message: Vec<u8> },
    /// Export a ghostkey's certificate and signing key for backup.
    /// Security-sensitive: returns the private signing key.
    ExportGhostKey { fingerprint: String },
    /// Export all ghostkeys for backup.
    ExportAllGhostKeys,
    /// Grant an application or delegate permission to use a ghostkey.
    GrantPermission {
        fingerprint: String,
        requestor: SignatureRequestor,
    },
    /// Revoke a previously granted permission.
    RevokePermission {
        fingerprint: String,
        requestor: SignatureRequestor,
    },
    /// List permissions for a ghostkey.
    ListPermissions { fingerprint: String },
    /// Debug: force a permission prompt regardless of existing permissions.
    TestPermissionPrompt { fingerprint: String },
    /// A third-party app asks for any one of the user's ghostkeys. The
    /// delegate emits a user prompt that lets the user pick a key (or
    /// deny). On approval the delegate grants `{ReadPublic, Sign}` to
    /// the requesting app for the chosen fingerprint and replies with a
    /// single-element `GhostKeyList` containing that key.
    ///
    /// The request takes no fields on purpose: the only identifier the
    /// user sees in the prompt is the runtime-attested requestor (a
    /// truncated contract id). Letting the app supply free text would
    /// open a phishing surface (a hostile app could write text designed
    /// to look like Freenet UI chrome). Apps that want to communicate
    /// purpose to the user should do so in their own UI before this
    /// flow runs.
    RequestAnyAccess,
}

/// Responses from the ghostkey delegate.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[non_exhaustive]
pub enum GhostkeyResponse {
    ImportResult {
        fingerprint: String,
        #[serde(rename = "delegate_info")]
        notary_info: String,
    },
    GhostKeyList {
        keys: Vec<GhostKeyInfo>,
    },
    GhostKeyDetail {
        fingerprint: String,
        certificate_pem: String,
        label: Option<String>,
        #[serde(rename = "delegate_info")]
        notary_info: String,
    },
    Certificate {
        fingerprint: String,
        certificate_pem: String,
    },
    SignResult {
        /// CBOR-serialized ScopedPayload
        scoped_payload: Vec<u8>,
        /// Ed25519 signature over the scoped_payload bytes
        signature: Vec<u8>,
        /// The certificate PEM, so the verifier has the full chain
        certificate_pem: String,
    },
    DefaultKeyResult {
        fingerprint: Option<String>,
    },
    DefaultKeySet {
        fingerprint: String,
    },
    VerifyResult {
        valid: bool,
        signer_fingerprint: Option<String>,
        #[serde(rename = "delegate_info")]
        notary_info: Option<String>,
        requestor: Option<SignatureRequestor>,
        message: Option<Vec<u8>>,
    },
    Deleted {
        fingerprint: String,
    },
    LabelSet {
        fingerprint: String,
        label: String,
    },
    PermissionGranted {
        fingerprint: String,
        requestor: SignatureRequestor,
    },
    PermissionRevoked {
        fingerprint: String,
        requestor: SignatureRequestor,
    },
    PermissionList {
        fingerprint: String,
        requestors: Vec<SignatureRequestor>,
    },
    ExportResult {
        fingerprint: String,
        certificate_pem: String,
        signing_key_pem: String,
        label: Option<String>,
    },
    ExportAllResult {
        keys: Vec<ExportedGhostKey>,
    },
    PermissionDenied {
        fingerprint: String,
        requestor: SignatureRequestor,
    },
    /// Permission denied for a request that didn't name a specific
    /// fingerprint -- today this means the user denied a
    /// `RequestAnyAccess` prompt. Distinct from `PermissionDenied` so
    /// callers don't have to invent a placeholder fingerprint to
    /// pattern-match.
    AccessDenied {
        requestor: SignatureRequestor,
    },
    /// The user has no ghostkeys. Apps should direct the user to
    /// freenet.org/ghostkey to purchase one.
    NoIdentityAvailable,
    /// The requested ghostkey fingerprint was not found.
    KeyNotFound {
        fingerprint: String,
    },
    /// Generic error for unexpected failures.
    Error {
        message: String,
    },
}
