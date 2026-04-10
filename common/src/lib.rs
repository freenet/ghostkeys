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
pub enum SignatureRequestor {
    /// A web application (UI) backed by this contract.
    WebApp(ContractInstanceId),
    /// Another delegate on the same node.
    Delegate(DelegateKey),
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
    /// The delegate certificate info field (encodes donation tier).
    pub delegate_info: String,
}

/// Requests from UI or other delegates to the ghostkey delegate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GhostkeyRequest {
    /// Import a ghostkey from PEM-armored certificate and signing key.
    ImportGhostKey {
        certificate_pem: String,
        signing_key_pem: String,
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
    /// Sign a message. The delegate scopes the signature to the requestor.
    /// Returns a ScopedPayload signature, not a raw signature.
    SignMessage {
        fingerprint: String,
        message: Vec<u8>,
    },
    /// Verify a signed message produced by this delegate.
    VerifySignedMessage { signed_message: Vec<u8> },
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
}

/// Responses from the ghostkey delegate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GhostkeyResponse {
    ImportResult {
        fingerprint: String,
        delegate_info: String,
    },
    GhostKeyList {
        keys: Vec<GhostKeyInfo>,
    },
    GhostKeyDetail {
        fingerprint: String,
        certificate_pem: String,
        label: Option<String>,
        delegate_info: String,
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
    VerifyResult {
        valid: bool,
        signer_fingerprint: Option<String>,
        delegate_info: Option<String>,
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
    PermissionDenied {
        fingerprint: String,
        requestor: SignatureRequestor,
    },
    Error {
        message: String,
    },
}
