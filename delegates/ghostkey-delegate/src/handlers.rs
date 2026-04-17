use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use freenet_stdlib::prelude::DelegateCtx;
use ghostkey_common::*;
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;

use crate::logging;
use crate::permissions;

const INDEX_KEY: &[u8] = b"gk:index";

fn cert_key(fp: &str) -> Vec<u8> {
    format!("gk:cert:{fp}").into_bytes()
}
fn sk_key(fp: &str) -> Vec<u8> {
    format!("gk:sk:{fp}").into_bytes()
}
fn label_key(fp: &str) -> Vec<u8> {
    format!("gk:label:{fp}").into_bytes()
}

/// Load the fingerprint index from secrets.
fn load_index(ctx: &DelegateCtx) -> Vec<String> {
    ctx.get_secret(INDEX_KEY)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

/// Save the fingerprint index to secrets.
fn save_index(ctx: &mut DelegateCtx, index: &[String]) {
    if let Ok(bytes) = to_cbor(&index) {
        ctx.set_secret(INDEX_KEY, &bytes);
    }
}

/// Load a certificate from secrets.
fn load_cert(ctx: &DelegateCtx, fp: &str) -> Option<GhostkeyCertificateV1> {
    let bytes = ctx.get_secret(&cert_key(fp))?;
    Armorable::from_bytes(&bytes).ok()
}

/// Get the notary info string from a certificate.
fn notary_info(cert: &GhostkeyCertificateV1) -> String {
    cert.notary.payload.info.clone()
}

pub fn handle(
    ctx: &mut DelegateCtx,
    request: GhostkeyRequest,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    match request {
        GhostkeyRequest::ImportGhostKey {
            certificate_pem,
            signing_key_pem,
            master_verifying_key_pem,
        } => handle_import(
            ctx,
            &certificate_pem,
            &signing_key_pem,
            master_verifying_key_pem.as_deref(),
            requestor,
        ),

        GhostkeyRequest::ListGhostKeys => handle_list(ctx, requestor),

        GhostkeyRequest::GetGhostKey { fingerprint } => {
            handle_get_detail(ctx, &fingerprint, requestor)
        }

        GhostkeyRequest::GetCertificate { fingerprint } => {
            handle_get_certificate(ctx, &fingerprint, requestor)
        }

        GhostkeyRequest::DeleteGhostKey { fingerprint } => {
            handle_delete(ctx, &fingerprint, requestor)
        }

        GhostkeyRequest::SetLabel { fingerprint, label } => {
            handle_set_label(ctx, &fingerprint, &label, requestor)
        }

        GhostkeyRequest::SignMessage {
            fingerprint,
            message,
        } => handle_sign(ctx, &fingerprint, &message, requestor),

        GhostkeyRequest::SignWithDefault { message } => {
            handle_sign_with_default(ctx, &message, requestor)
        }

        GhostkeyRequest::SetDefaultKey { fingerprint } => {
            handle_set_default(ctx, &fingerprint, requestor)
        }

        GhostkeyRequest::GetDefaultKey => handle_get_default(ctx, requestor),

        GhostkeyRequest::VerifySignedMessage { signed_message } => handle_verify(&signed_message),

        GhostkeyRequest::ExportGhostKey { fingerprint } => {
            handle_export(ctx, &fingerprint, requestor)
        }

        GhostkeyRequest::ExportAllGhostKeys => handle_export_all(ctx, requestor),

        GhostkeyRequest::GrantPermission {
            fingerprint,
            requestor: target,
        } => handle_grant_permission(ctx, &fingerprint, &target, requestor),

        GhostkeyRequest::RevokePermission {
            fingerprint,
            requestor: target,
        } => handle_revoke_permission(ctx, &fingerprint, &target, requestor),

        GhostkeyRequest::ListPermissions { fingerprint } => {
            handle_list_permissions(ctx, &fingerprint, requestor)
        }

        GhostkeyRequest::TestPermissionPrompt { .. } => {
            // Handled in lib.rs before reaching here; if we get here
            // it means the user approved the prompt, return success
            GhostkeyResponse::Error {
                message: "Test prompt approved".into(),
            }
        }

        // Required by `#[non_exhaustive]` on GhostkeyRequest so adding new
        // request variants in future ghostkey-common releases is not a
        // breaking change. A delegate built against an older ghostkey-common
        // version will never see these variants; if we somehow do (because
        // the UI was built against a newer common), reject cleanly.
        _ => GhostkeyResponse::Error {
            message: "Unsupported request variant for this delegate version".into(),
        },
    }
}

fn handle_import(
    ctx: &mut DelegateCtx,
    certificate_pem: &str,
    signing_key_pem: &str,
    master_verifying_key_pem: Option<&str>,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    // Deserialize certificate
    let cert: GhostkeyCertificateV1 = match Armorable::from_armored_string(certificate_pem) {
        Ok(c) => c,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("invalid certificate PEM: {e}"),
            }
        }
    };

    // Parse optional master verifying key override (for testing)
    let master_vk: Option<VerifyingKey> = match master_verifying_key_pem {
        Some(pem) => match Armorable::from_armored_string(pem) {
            Ok(vk) => Some(vk),
            Err(e) => {
                return GhostkeyResponse::Error {
                    message: format!("invalid master verifying key PEM: {e}"),
                }
            }
        },
        None => None,
    };

    // Verify certificate chain (back to master key, or provided key)
    let info = match cert.verify(&master_vk) {
        Ok(info) => info,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("certificate verification failed: {e}"),
            }
        }
    };

    // Deserialize signing key
    let sk: SigningKey = match Armorable::from_armored_string(signing_key_pem) {
        Ok(sk) => sk,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("invalid signing key PEM: {e}"),
            }
        }
    };

    // Confirm signing key matches certificate's verifying key
    let vk: VerifyingKey = (&sk).into();
    if vk != cert.verifying_key {
        return GhostkeyResponse::Error {
            message: "signing key does not match certificate's verifying key".into(),
        };
    }

    // Compute fingerprint
    let fp = fingerprint(&cert.verifying_key);
    logging::info(&format!("Importing ghostkey {fp}"));

    // Store certificate (CBOR)
    let cert_bytes = match Armorable::to_bytes(&cert) {
        Ok(b) => b,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("serialize certificate: {e}"),
            }
        }
    };
    ctx.set_secret(&cert_key(&fp), &cert_bytes);

    // Store signing key (raw 32 bytes)
    ctx.set_secret(&sk_key(&fp), sk.as_bytes());

    // Update index
    let mut index = load_index(ctx);
    if !index.contains(&fp) {
        index.push(fp.clone());
        save_index(ctx, &index);
    }

    // Auto-grant permission to the importing requestor
    permissions::grant(ctx, &fp, requestor);

    GhostkeyResponse::ImportResult {
        fingerprint: fp,
        notary_info: info,
    }
}

fn handle_list(ctx: &DelegateCtx, requestor: &SignatureRequestor) -> GhostkeyResponse {
    let index = load_index(ctx);
    let mut keys = Vec::new();

    for fp in &index {
        // Only show ghostkeys the requestor has permission for
        if !permissions::is_allowed(ctx, fp, requestor) {
            continue;
        }

        if let Some(cert) = load_cert(ctx, fp) {
            let label = ctx
                .get_secret(&label_key(fp))
                .and_then(|b| String::from_utf8(b).ok());
            keys.push(GhostKeyInfo {
                fingerprint: fp.clone(),
                label,
                notary_info: notary_info(&cert),
                verifying_key_bytes: Some(cert.verifying_key.as_bytes().to_vec()),
            });
        }
    }

    GhostkeyResponse::GhostKeyList { keys }
}

fn handle_get_detail(
    ctx: &DelegateCtx,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    let cert = match load_cert(ctx, fp) {
        Some(c) => c,
        None => {
            return GhostkeyResponse::KeyNotFound {
                fingerprint: fp.to_string(),
            }
        }
    };

    let certificate_pem = match Armorable::to_armored_string(&cert) {
        Ok(s) => s,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("serialize certificate: {e}"),
            }
        }
    };

    let label = ctx
        .get_secret(&label_key(fp))
        .and_then(|b| String::from_utf8(b).ok());

    GhostkeyResponse::GhostKeyDetail {
        fingerprint: fp.to_string(),
        certificate_pem,
        label,
        notary_info: notary_info(&cert),
    }
}

fn handle_get_certificate(
    ctx: &DelegateCtx,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    let cert = match load_cert(ctx, fp) {
        Some(c) => c,
        None => {
            return GhostkeyResponse::KeyNotFound {
                fingerprint: fp.to_string(),
            }
        }
    };

    let certificate_pem = match Armorable::to_armored_string(&cert) {
        Ok(s) => s,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("serialize certificate: {e}"),
            }
        }
    };

    GhostkeyResponse::Certificate {
        fingerprint: fp.to_string(),
        certificate_pem,
    }
}

fn handle_delete(
    ctx: &mut DelegateCtx,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    ctx.remove_secret(&cert_key(fp));
    ctx.remove_secret(&sk_key(fp));
    ctx.remove_secret(&label_key(fp));

    let mut index = load_index(ctx);
    index.retain(|f| f != fp);
    save_index(ctx, &index);

    logging::info(&format!("Deleted ghostkey {fp}"));

    GhostkeyResponse::Deleted {
        fingerprint: fp.to_string(),
    }
}

fn handle_set_label(
    ctx: &mut DelegateCtx,
    fp: &str,
    label: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    if !load_index(ctx).contains(&fp.to_string()) {
        return GhostkeyResponse::KeyNotFound {
            fingerprint: fp.to_string(),
        };
    }

    ctx.set_secret(&label_key(fp), label.as_bytes());

    GhostkeyResponse::LabelSet {
        fingerprint: fp.to_string(),
        label: label.to_string(),
    }
}

const DEFAULT_KEY: &[u8] = b"gk:default";

/// Resolve the default ghostkey fingerprint: explicit default, or highest-tier.
fn resolve_default(ctx: &DelegateCtx, requestor: &SignatureRequestor) -> Option<String> {
    // Check explicit default
    if let Some(bytes) = ctx.get_secret(DEFAULT_KEY) {
        if let Ok(fp) = String::from_utf8(bytes) {
            // Verify it still exists and we have permission
            if load_cert(ctx, &fp).is_some() && permissions::is_allowed(ctx, &fp, requestor) {
                return Some(fp);
            }
        }
    }

    // Fall back to highest-tier key we have permission for
    let index = load_index(ctx);
    let mut best: Option<(String, u32)> = None;

    for fp in &index {
        if !permissions::is_allowed(ctx, fp, requestor) {
            continue;
        }
        if let Some(cert) = load_cert(ctx, fp) {
            let info = notary_info(&cert);
            let amount = extract_amount(&info).unwrap_or(0);
            if best
                .as_ref()
                .map_or(true, |(_, best_amt)| amount > *best_amt)
            {
                best = Some((fp.clone(), amount));
            }
        }
    }

    best.map(|(fp, _)| fp)
}

/// Extract donation amount from notary info string.
fn extract_amount(info: &str) -> Option<u32> {
    if info.starts_with('{') {
        // JSON: {"amount":1,...}
        if let Some(pos) = info.find("\"amount\":") {
            let after = &info[pos + 9..];
            let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            return num_str.parse().ok();
        }
        None
    } else {
        info.strip_prefix("donation_amount:")
            .and_then(|a| a.parse().ok())
    }
}

fn handle_sign_with_default(
    ctx: &DelegateCtx,
    message: &[u8],
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    match resolve_default(ctx, requestor) {
        Some(fp) => handle_sign(ctx, &fp, message, requestor),
        None => GhostkeyResponse::NoIdentityAvailable,
    }
}

fn handle_set_default(
    ctx: &mut DelegateCtx,
    fingerprint: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fingerprint, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fingerprint.to_string(),
            requestor: requestor.clone(),
        };
    }

    if load_cert(ctx, fingerprint).is_none() {
        return GhostkeyResponse::KeyNotFound {
            fingerprint: fingerprint.to_string(),
        };
    }

    ctx.set_secret(DEFAULT_KEY, fingerprint.as_bytes());
    logging::info(&format!("Default ghostkey set to {fingerprint}"));

    GhostkeyResponse::DefaultKeySet {
        fingerprint: fingerprint.to_string(),
    }
}

fn handle_get_default(ctx: &DelegateCtx, requestor: &SignatureRequestor) -> GhostkeyResponse {
    let fp = resolve_default(ctx, requestor);
    GhostkeyResponse::DefaultKeyResult { fingerprint: fp }
}

fn handle_sign(
    ctx: &DelegateCtx,
    fp: &str,
    message: &[u8],
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    // Load signing key
    let sk_bytes = match ctx.get_secret(&sk_key(fp)) {
        Some(b) => b,
        None => {
            return GhostkeyResponse::Error {
                message: format!("signing key for {fp} not found"),
            }
        }
    };

    let sk_array: [u8; 32] = match sk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return GhostkeyResponse::Error {
                message: "corrupt signing key".into(),
            }
        }
    };
    let signing_key = SigningKey::from_bytes(&sk_array);

    // Load certificate for PEM
    let cert = match load_cert(ctx, fp) {
        Some(c) => c,
        None => {
            return GhostkeyResponse::Error {
                message: format!("certificate for {fp} not found"),
            }
        }
    };

    let certificate_pem = match Armorable::to_armored_string(&cert) {
        Ok(s) => s,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("serialize certificate: {e}"),
            }
        }
    };

    // Build scoped payload
    let scoped = ScopedPayload {
        requestor: requestor.clone(),
        payload: message.to_vec(),
    };

    let scoped_bytes = match to_cbor(&scoped) {
        Ok(b) => b,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("serialize scoped payload: {e}"),
            }
        }
    };

    // Sign the scoped payload bytes
    let signature = signing_key.sign(&scoped_bytes);

    logging::info(&format!("Signed message with ghostkey {fp}"));

    GhostkeyResponse::SignResult {
        scoped_payload: scoped_bytes,
        signature: signature.to_bytes().to_vec(),
        certificate_pem,
    }
}

fn handle_verify(signed_message: &[u8]) -> GhostkeyResponse {
    // The signed_message is expected to be CBOR: { scoped_payload, signature, certificate_pem }
    #[derive(serde::Deserialize)]
    struct SignedBundle {
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
        certificate_pem: String,
    }

    let bundle: SignedBundle = match from_cbor(signed_message) {
        Ok(b) => b,
        Err(_) => {
            return GhostkeyResponse::VerifyResult {
                valid: false,
                signer_fingerprint: None,
                notary_info: None,
                requestor: None,
                message: None,
            }
        }
    };

    // Parse certificate
    let cert: GhostkeyCertificateV1 = match Armorable::from_armored_string(&bundle.certificate_pem)
    {
        Ok(c) => c,
        Err(_) => {
            return GhostkeyResponse::VerifyResult {
                valid: false,
                signer_fingerprint: None,
                notary_info: None,
                requestor: None,
                message: None,
            }
        }
    };

    // Verify certificate chain
    let info = match cert.verify(&None) {
        Ok(info) => info,
        Err(_) => {
            return GhostkeyResponse::VerifyResult {
                valid: false,
                signer_fingerprint: None,
                notary_info: None,
                requestor: None,
                message: None,
            }
        }
    };

    // Parse signature
    let sig_bytes: [u8; 64] = match bundle.signature.try_into() {
        Ok(b) => b,
        Err(_) => {
            return GhostkeyResponse::VerifyResult {
                valid: false,
                signer_fingerprint: None,
                notary_info: None,
                requestor: None,
                message: None,
            }
        }
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    // Verify Ed25519 signature over scoped payload
    use ed25519_dalek::Verifier;
    if cert
        .verifying_key
        .verify(&bundle.scoped_payload, &signature)
        .is_err()
    {
        return GhostkeyResponse::VerifyResult {
            valid: false,
            signer_fingerprint: Some(fingerprint(&cert.verifying_key)),
            notary_info: Some(info),
            requestor: None,
            message: None,
        };
    }

    // Decode scoped payload
    let scoped: ScopedPayload = match from_cbor(&bundle.scoped_payload) {
        Ok(s) => s,
        Err(_) => {
            return GhostkeyResponse::VerifyResult {
                valid: false,
                signer_fingerprint: Some(fingerprint(&cert.verifying_key)),
                notary_info: Some(info),
                requestor: None,
                message: None,
            }
        }
    };

    GhostkeyResponse::VerifyResult {
        valid: true,
        signer_fingerprint: Some(fingerprint(&cert.verifying_key)),
        notary_info: Some(info),
        requestor: Some(scoped.requestor),
        message: Some(scoped.payload),
    }
}

fn handle_export(ctx: &DelegateCtx, fp: &str, requestor: &SignatureRequestor) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    let cert = match load_cert(ctx, fp) {
        Some(c) => c,
        None => {
            return GhostkeyResponse::KeyNotFound {
                fingerprint: fp.to_string(),
            }
        }
    };

    let certificate_pem = match Armorable::to_armored_string(&cert) {
        Ok(s) => s,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("serialize certificate: {e}"),
            }
        }
    };

    let sk_bytes = match ctx.get_secret(&sk_key(fp)) {
        Some(b) => b,
        None => {
            return GhostkeyResponse::Error {
                message: format!("signing key for {fp} not found"),
            }
        }
    };

    let sk_array: [u8; 32] = match sk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return GhostkeyResponse::Error {
                message: "corrupt signing key".into(),
            }
        }
    };
    let signing_key = SigningKey::from_bytes(&sk_array);
    let signing_key_pem = match Armorable::to_armored_string(&signing_key) {
        Ok(s) => s,
        Err(e) => {
            return GhostkeyResponse::Error {
                message: format!("serialize signing key: {e}"),
            }
        }
    };

    let label = ctx
        .get_secret(&label_key(fp))
        .and_then(|b| String::from_utf8(b).ok());

    GhostkeyResponse::ExportResult {
        fingerprint: fp.to_string(),
        certificate_pem,
        signing_key_pem,
        label,
    }
}

fn handle_export_all(ctx: &DelegateCtx, requestor: &SignatureRequestor) -> GhostkeyResponse {
    let index = load_index(ctx);
    let mut keys = Vec::new();

    for fp in &index {
        if !permissions::is_allowed(ctx, fp, requestor) {
            continue;
        }

        let cert = match load_cert(ctx, fp) {
            Some(c) => c,
            None => continue,
        };

        let certificate_pem = match Armorable::to_armored_string(&cert) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let sk_bytes = match ctx.get_secret(&sk_key(fp)) {
            Some(b) => b,
            None => continue,
        };

        let sk_array: [u8; 32] = match sk_bytes.try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let signing_key = SigningKey::from_bytes(&sk_array);
        let signing_key_pem = match Armorable::to_armored_string(&signing_key) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let label = ctx
            .get_secret(&label_key(fp))
            .and_then(|b| String::from_utf8(b).ok());

        keys.push(ExportedGhostKey {
            fingerprint: fp.clone(),
            certificate_pem,
            signing_key_pem,
            label,
            notary_info: notary_info(&cert),
        });
    }

    GhostkeyResponse::ExportAllResult { keys }
}

fn handle_grant_permission(
    ctx: &mut DelegateCtx,
    fp: &str,
    target: &SignatureRequestor,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    // Only the ghostkey management UI (the importer) can grant permissions.
    // We check that the requestor already has permission for this ghostkey.
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    permissions::grant(ctx, fp, target);

    GhostkeyResponse::PermissionGranted {
        fingerprint: fp.to_string(),
        requestor: target.clone(),
    }
}

fn handle_revoke_permission(
    ctx: &mut DelegateCtx,
    fp: &str,
    target: &SignatureRequestor,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    permissions::revoke(ctx, fp, target);

    GhostkeyResponse::PermissionRevoked {
        fingerprint: fp.to_string(),
        requestor: target.clone(),
    }
}

fn handle_list_permissions(
    ctx: &DelegateCtx,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::is_allowed(ctx, fp, requestor) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    let requestors = permissions::list(ctx, fp);

    GhostkeyResponse::PermissionList {
        fingerprint: fp.to_string(),
        requestors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_rejects_invalid_data() {
        let result = handle_verify(b"not valid cbor at all");
        match result {
            GhostkeyResponse::VerifyResult { valid, .. } => assert!(!valid),
            _ => panic!("expected VerifyResult"),
        }
    }
}
