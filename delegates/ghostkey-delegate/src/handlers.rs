use crate::env::DelegateEnv;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
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
/// Marker recording that the user has exported this identity at least once.
/// Presence is the whole signal; the value is never read.
fn backed_up_key(fp: &str) -> Vec<u8> {
    format!("gk:backedup:{fp}").into_bytes()
}

fn is_backed_up(ctx: &dyn DelegateEnv, fp: &str) -> bool {
    ctx.get_secret(&backed_up_key(fp)).is_some()
}

/// The user-set label for a ghostkey, if any. Used by `lib.rs` to show a
/// name the user picked instead of a raw fingerprint in permission prompts.
pub(crate) fn get_label(ctx: &dyn DelegateEnv, fp: &str) -> Option<String> {
    ctx.get_secret(&label_key(fp))
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.trim().is_empty())
}

/// Load the fingerprint index from secrets. Exposed at crate visibility
/// so the `RequestAnyAccess` prompt path in `lib.rs` can list keys for
/// the user without recreating the storage layout knowledge.
pub(crate) fn load_index(ctx: &dyn DelegateEnv) -> Vec<String> {
    ctx.get_secret(INDEX_KEY)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

/// Save the fingerprint index to secrets.
fn save_index(ctx: &mut dyn DelegateEnv, index: &[String]) {
    if let Ok(bytes) = to_cbor(&index) {
        ctx.set_secret(INDEX_KEY, &bytes);
    }
}

/// Load a certificate from secrets.
fn load_cert(ctx: &dyn DelegateEnv, fp: &str) -> Option<GhostkeyCertificateV1> {
    let bytes = ctx.get_secret(&cert_key(fp))?;
    Armorable::from_bytes(&bytes).ok()
}

/// Get the notary info string from a certificate.
fn notary_info(cert: &GhostkeyCertificateV1) -> String {
    cert.notary.payload.info.clone()
}

pub fn handle(
    ctx: &mut dyn DelegateEnv,
    request: GhostkeyRequest,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    match request {
        GhostkeyRequest::ImportGhostKey {
            certificate_pem,
            signing_key_pem,
        } => handle_import(ctx, &certificate_pem, &signing_key_pem, requestor),

        GhostkeyRequest::ListGhostKeys => handle_list(ctx, requestor),

        GhostkeyRequest::HasIdentity => handle_has_identity(ctx, requestor),

        GhostkeyRequest::MarkBackedUp { fingerprint } => {
            handle_mark_backed_up(ctx, &fingerprint, requestor)
        }

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
    ctx: &mut dyn DelegateEnv,
    certificate_pem: &str,
    signing_key_pem: &str,
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

    // Verify the certificate chain against the Freenet master key compiled
    // into the delegate. `None` here means "the built-in trust root", and it
    // is the only one the vault will accept.
    //
    // do NOT re-add a master-key override parameter -- see the doc comment on
    // `GhostkeyRequest::ImportGhostKey`.
    let info = match cert.verify(&None) {
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

    // Auto-grant the full scope set to the importing requestor. The
    // importer (typically the vault) is the user's agent for this key
    // and gets every scope the delegate enforces, including Admin so it
    // can manage other apps' grants on the user's behalf.
    permissions::grant_full(ctx, &fp, requestor);

    GhostkeyResponse::ImportResult {
        fingerprint: fp,
        notary_info: info,
    }
}

/// Build a `GhostKeyList` containing exactly the named key, with no
/// permission filtering. Used by the `RequestAnyAccess` approval path so
/// the response carries only the fingerprint the user just chose to
/// share -- routing through `handle_list` would leak any other keys the
/// requestor previously had `ReadPublic` on.
pub(crate) fn lookup_single_key(ctx: &dyn DelegateEnv, fp: &str) -> GhostkeyResponse {
    match load_cert(ctx, fp) {
        Some(cert) => {
            let label = ctx
                .get_secret(&label_key(fp))
                .and_then(|b| String::from_utf8(b).ok());
            GhostkeyResponse::GhostKeyList {
                keys: vec![GhostKeyInfo {
                    fingerprint: fp.to_string(),
                    label,
                    notary_info: notary_info(&cert),
                    verifying_key_bytes: Some(cert.verifying_key.as_bytes().to_vec()),
                    backed_up: is_backed_up(ctx, fp),
                }],
            }
        }
        // The fp came from `load_index(ctx)` at prompt-emit time, so
        // missing here means the cert was deleted between prompt and
        // approval. Fall through to KeyNotFound rather than an empty
        // list, which would otherwise look like a successful share with
        // a zero-element result.
        None => GhostkeyResponse::KeyNotFound {
            fingerprint: fp.to_string(),
        },
    }
}

/// One indexed fingerprint as `handle_has_identity` sees it.
#[derive(Debug, Clone, Copy)]
struct KeySlot {
    has_certificate: bool,
    has_signing_key: bool,
    /// Whether the asking caller holds `ReadPublic` on this key.
    caller_may_read: bool,
}

/// Answer "does the user hold a ghostkey?" without prompting and without
/// naming anything.
///
/// The answer is bounded by scope. `HasIdentity` still never prompts and still
/// answers a caller that holds no grant -- that is the whole reason it exists,
/// and removing it would send a user who already paid for a ghostkey off to buy
/// a second one -- but what it discloses is now proportionate to what the
/// caller has been allowed to see. See [`scoped_presence`] for the split.
fn handle_has_identity(ctx: &dyn DelegateEnv, requestor: &SignatureRequestor) -> GhostkeyResponse {
    let slots: Vec<KeySlot> = load_index(ctx)
        .iter()
        .map(|fp| KeySlot {
            has_certificate: load_cert(ctx, fp).is_some(),
            has_signing_key: ctx.get_secret(&sk_key(fp)).is_some(),
            caller_may_read: permissions::has_scope(ctx, fp, requestor, GhostkeyScope::ReadPublic),
        })
        .collect();

    let (usable, unusable) = scoped_presence(&slots);
    GhostkeyResponse::IdentityPresence { usable, unusable }
}

/// Pure scope filter behind `handle_has_identity`.
///
/// Two cases, and the difference between them is the whole point:
///
/// - **The caller holds `ReadPublic` on something.** It gets the true counts
///   for those keys and nothing about the rest. A grant on one key is not
///   consent to be told how large the vault is.
/// - **The caller holds nothing.** It gets existence and nothing more: each
///   count saturates at one. That is exactly the bit `NoIdentityAvailable`
///   already discloses to anyone who asks for a signature, so nothing new
///   leaks, and it is still enough to answer "should I offer to sell this
///   person a ghostkey?" and "is the one they have broken?".
///
/// An empty vault answers `(0, 0)` in both cases, which is the honest answer
/// and the one the purchase round-trip depends on.
fn scoped_presence(slots: &[KeySlot]) -> (usize, usize) {
    let readable: Vec<(bool, bool)> = slots
        .iter()
        .filter(|s| s.caller_may_read)
        .map(|s| (s.has_certificate, s.has_signing_key))
        .collect();

    if !readable.is_empty() {
        return tally_presence(&readable);
    }

    let all: Vec<(bool, bool)> = slots
        .iter()
        .map(|s| (s.has_certificate, s.has_signing_key))
        .collect();
    let (usable, unusable) = tally_presence(&all);
    (usable.min(1), unusable.min(1))
}

/// Pure tally behind `handle_has_identity`. One `(has_certificate,
/// has_signing_key)` entry per indexed fingerprint; returns `(usable,
/// unusable)`.
///
/// A certificate with no signing key is listed by `handle_list` and looks
/// healthy, but cannot sign. Counting it separately is what lets the vault
/// warn about it rather than offer a broken identity. An index entry whose
/// certificate is gone is counted as neither -- there is nothing left to
/// recover, and reporting it as `unusable` would nag about a key that no
/// longer exists.
fn tally_presence(slots: &[(bool, bool)]) -> (usize, usize) {
    let mut usable = 0usize;
    let mut unusable = 0usize;
    for &(has_cert, has_sk) in slots {
        match (has_cert, has_sk) {
            (true, true) => usable += 1,
            (true, false) => unusable += 1,
            (false, _) => {}
        }
    }
    (usable, unusable)
}

/// Record that the user holds a copy of this identity outside the vault.
///
/// Gated on `Export` — the scope that is only ever granted to the vault — so a
/// third-party app cannot silence a warning about a key it has no backup of.
fn handle_mark_backed_up(
    ctx: &mut dyn DelegateEnv,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Export) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    if load_cert(ctx, fp).is_none() {
        return GhostkeyResponse::KeyNotFound {
            fingerprint: fp.to_string(),
        };
    }

    ctx.set_secret(&backed_up_key(fp), b"1");
    GhostkeyResponse::BackedUpMarked {
        fingerprint: fp.to_string(),
    }
}

fn handle_list(ctx: &dyn DelegateEnv, requestor: &SignatureRequestor) -> GhostkeyResponse {
    let index = load_index(ctx);
    let mut keys = Vec::new();

    for fp in &index {
        // Only show ghostkeys the requestor has at least ReadPublic on.
        // Sign / Export / Delete grants always include ReadPublic so an
        // app with any visible-to-them grant lists the key.
        if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::ReadPublic) {
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
                backed_up: is_backed_up(ctx, fp),
            });
        }
    }

    GhostkeyResponse::GhostKeyList { keys }
}

fn handle_get_detail(
    ctx: &dyn DelegateEnv,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::ReadPublic) {
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
    ctx: &dyn DelegateEnv,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::ReadPublic) {
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
    ctx: &mut dyn DelegateEnv,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Delete) {
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
    ctx: &mut dyn DelegateEnv,
    fp: &str,
    label: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Delete) {
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
pub(crate) fn resolve_default(
    ctx: &dyn DelegateEnv,
    requestor: &SignatureRequestor,
) -> Option<String> {
    // The "default key" is selected for signing, so the requestor needs
    // Sign on it. ReadPublic alone wouldn't be enough -- a third-party
    // app that hasn't been granted Sign for any key shouldn't get a
    // signing fp from this resolver.
    if let Some(bytes) = ctx.get_secret(DEFAULT_KEY) {
        if let Ok(fp) = String::from_utf8(bytes) {
            if load_cert(ctx, &fp).is_some()
                && permissions::has_scope(ctx, &fp, requestor, GhostkeyScope::Sign)
            {
                return Some(fp);
            }
        }
    }

    // Fall back to the highest-tier key the requestor can sign with.
    let index = load_index(ctx);
    let mut best: Option<(String, u32)> = None;

    for fp in &index {
        if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Sign) {
            continue;
        }
        if let Some(cert) = load_cert(ctx, fp) {
            let info = notary_info(&cert);
            let amount = extract_amount(&info).unwrap_or(0);
            if best.as_ref().is_none_or(|(_, best_amt)| amount > *best_amt) {
                best = Some((fp.clone(), amount));
            }
        }
    }

    best.map(|(fp, _)| fp)
}

/// Fingerprints that can actually sign, ordered the way `resolve_default`
/// ranks them: highest donation tier first, ties broken by index order.
///
/// Both filters matter for the signing picker this feeds:
///
/// - **Ranked, not index order.** The picker shows at most a handful of
///   buttons, so truncating import order would offer someone who bought a $5
///   key first and a $500 key tenth only the $5 one.
/// - **Signing key required, not just a certificate.** A half-lost identity
///   still has a certificate and would otherwise appear in the picker; the
///   user would approve it and get "signing key not found" back. Consent
///   should not be collected for something that cannot work.
///
/// Not permission-filtered: this exists for the prompt shown when the caller
/// has no grant on anything, so filtering by grant would return nothing.
pub(crate) fn signable_fingerprints_by_tier_desc(ctx: &dyn DelegateEnv) -> Vec<String> {
    let with_tiers: Vec<(String, u32)> = load_index(ctx)
        .into_iter()
        .filter_map(|fp| {
            let cert = load_cert(ctx, &fp)?;
            ctx.get_secret(&sk_key(&fp))?;
            let amount = extract_amount(&notary_info(&cert)).unwrap_or(0);
            Some((fp, amount))
        })
        .collect();
    rank_by_tier_desc(with_tiers)
}

/// Pure ranking behind `fingerprints_by_tier_desc`.
fn rank_by_tier_desc(mut with_tiers: Vec<(String, u32)>) -> Vec<String> {
    // Stable, so equal tiers keep index order and the prompt is reproducible.
    // A picker whose buttons move between showings is one people click through
    // without reading.
    with_tiers.sort_by_key(|(_, amount)| std::cmp::Reverse(*amount));
    with_tiers.into_iter().map(|(fp, _)| fp).collect()
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
    ctx: &dyn DelegateEnv,
    message: &[u8],
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    match resolve_default(ctx, requestor) {
        Some(fp) => handle_sign(ctx, &fp, message, requestor),
        None => GhostkeyResponse::NoIdentityAvailable,
    }
}

fn handle_set_default(
    ctx: &mut dyn DelegateEnv,
    fingerprint: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    // Setting the default-for-signing requires the caller to be able to
    // sign with the key.
    if !permissions::has_scope(ctx, fingerprint, requestor, GhostkeyScope::Sign) {
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

fn handle_get_default(ctx: &dyn DelegateEnv, requestor: &SignatureRequestor) -> GhostkeyResponse {
    let fp = resolve_default(ctx, requestor);
    GhostkeyResponse::DefaultKeyResult { fingerprint: fp }
}

fn handle_sign(
    ctx: &dyn DelegateEnv,
    fp: &str,
    message: &[u8],
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Sign) {
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

fn handle_export(
    ctx: &dyn DelegateEnv,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    // Export returns the private signing key. Catastrophic if granted to
    // a third-party app, so this scope is reserved for the vault.
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Export) {
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

/// How many stored ghostkeys `requestor` could actually extract via
/// `ExportAllGhostKeys`. Used by the export-confirmation prompt so it can tell
/// the user how many private keys are about to leave the vault, and so a
/// caller that could extract nothing never gets to raise a dialog at all.
pub(crate) fn exportable_count(ctx: &dyn DelegateEnv, requestor: &SignatureRequestor) -> usize {
    load_index(ctx)
        .iter()
        .filter(|fp| permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Export))
        .filter(|fp| load_cert(ctx, fp).is_some())
        .count()
}

fn handle_export_all(ctx: &dyn DelegateEnv, requestor: &SignatureRequestor) -> GhostkeyResponse {
    let index = load_index(ctx);
    let mut keys = Vec::new();

    for fp in &index {
        if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Export) {
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
    ctx: &mut dyn DelegateEnv,
    fp: &str,
    target: &SignatureRequestor,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    // Only callers with the Admin scope on this fingerprint can grant.
    // Admin is auto-given to the importer (the vault) and never granted
    // via `RequestAnyAccess`, so a third-party app with `{ReadPublic, Sign}`
    // cannot escalate by calling Grant.
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Admin) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    // Default-grant the third-party scope set so vault-mediated
    // share-with-app flows match the `RequestAnyAccess` semantics. A
    // future protocol bump can add a scoped variant for vault UIs that
    // want finer control.
    permissions::grant_third_party(ctx, fp, target);

    GhostkeyResponse::PermissionGranted {
        fingerprint: fp.to_string(),
        requestor: target.clone(),
    }
}

fn handle_revoke_permission(
    ctx: &mut dyn DelegateEnv,
    fp: &str,
    target: &SignatureRequestor,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::Admin) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    permissions::revoke_all(ctx, fp, target);

    GhostkeyResponse::PermissionRevoked {
        fingerprint: fp.to_string(),
        requestor: target.clone(),
    }
}

fn handle_list_permissions(
    ctx: &dyn DelegateEnv,
    fp: &str,
    requestor: &SignatureRequestor,
) -> GhostkeyResponse {
    // ReadPublic is enough to see the grant list. The vault has every
    // scope so it always passes; a third-party app with `Sign` access
    // can introspect who else holds grants on a key it can already
    // operate on (no extra capability surface).
    if !permissions::has_scope(ctx, fp, requestor, GhostkeyScope::ReadPublic) {
        return GhostkeyResponse::PermissionDenied {
            fingerprint: fp.to_string(),
            requestor: requestor.clone(),
        };
    }

    let requestors = permissions::list_requestors(ctx, fp);

    GhostkeyResponse::PermissionList {
        fingerprint: fp.to_string(),
        requestors,
    }
}

/// Test-only: generate a self-contained ghostkey (master key -> notary cert
/// -> ghostkey cert) with a throwaway master key.
///
/// Certificates a test can produce are signed by that throwaway key, never by
/// the production Freenet master key, so they cannot be pushed through
/// `handle_import` -- its chain check would (correctly) reject them. Seeding
/// via [`seed_ghostkey`] is therefore the only way to exercise the
/// authorization paths against a populated vault.
#[cfg(test)]
pub(crate) fn test_ghostkey(donation_amount: u32) -> (GhostkeyCertificateV1, SigningKey) {
    use ghostkey_lib::notary_certificate::NotaryCertificateV1;
    use rand_core::OsRng;

    let (master_sk, _master_vk) = ghostkey_lib::util::create_keypair(&mut OsRng).unwrap();
    let info = format!("donation_amount:{donation_amount}");
    let (notary_cert, notary_sk) = NotaryCertificateV1::new(&master_sk, &info).unwrap();
    GhostkeyCertificateV1::new(&notary_cert, &notary_sk)
}

/// Test-only: place a ghostkey in the vault exactly the way `handle_import`
/// does once verification has passed -- same secret-store layout, same
/// `grant_full` for the owner -- so a seeded vault cannot drift from a real
/// one. Returns the fingerprint.
#[cfg(test)]
pub(crate) fn seed_ghostkey(
    ctx: &mut dyn DelegateEnv,
    cert: &GhostkeyCertificateV1,
    sk: &SigningKey,
    owner: &SignatureRequestor,
) -> String {
    let fp = fingerprint(&cert.verifying_key);
    let cert_bytes = Armorable::to_bytes(cert).expect("serialize test certificate");
    ctx.set_secret(&cert_key(&fp), &cert_bytes);
    ctx.set_secret(&sk_key(&fp), sk.as_bytes());
    let mut index = load_index(ctx);
    if !index.contains(&fp) {
        index.push(fp.clone());
        save_index(ctx, &index);
    }
    permissions::grant_full(ctx, &fp, owner);
    fp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MemEnv;
    use freenet_stdlib::prelude::ContractInstanceId;

    fn webapp(seed: u8) -> SignatureRequestor {
        let bytes = [seed; 32];
        let id = ContractInstanceId::from_bytes(bs58::encode(&bytes).into_string()).unwrap();
        SignatureRequestor::WebApp(id)
    }

    /// Regression: `HasIdentity` used to tally the WHOLE vault for any
    /// caller, so an app with no grant on anything -- and an app granted a
    /// single key -- both learned exactly how many identities the user holds
    /// and how many of them are broken. The answer must be bounded by what the
    /// caller has been allowed to see.
    #[test]
    fn has_identity_counts_only_keys_the_caller_may_read() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let app = webapp(0x02);

        let mut fps = Vec::new();
        for tier in [10u32, 20, 30] {
            let (cert, sk) = test_ghostkey(tier);
            fps.push(seed_ghostkey(&mut env, &cert, &sk, &vault));
        }
        // The app is allowed to see exactly one of the three.
        permissions::grant_third_party(&mut env, &fps[1], &app);

        match handle_has_identity(&env, &app) {
            GhostkeyResponse::IdentityPresence { usable, unusable } => {
                assert_eq!(
                    (usable, unusable),
                    (1, 0),
                    "an app granted one key must not learn that the vault holds three"
                );
            }
            other => panic!("expected IdentityPresence, got {other:?}"),
        }

        // The vault itself imported all three, so it still sees all three.
        match handle_has_identity(&env, &vault) {
            GhostkeyResponse::IdentityPresence { usable, unusable } => {
                assert_eq!((usable, unusable), (3, 0));
            }
            other => panic!("expected IdentityPresence, got {other:?}"),
        }
    }

    /// The other half of the same regression: a caller with no grant at all
    /// still gets a truthful existence answer -- that is what `HasIdentity`
    /// exists for -- but not a headcount.
    #[test]
    fn has_identity_discloses_existence_but_not_headcount_to_an_ungranted_caller() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let stranger = webapp(0x03);

        for tier in [10u32, 20, 30] {
            let (cert, sk) = test_ghostkey(tier);
            seed_ghostkey(&mut env, &cert, &sk, &vault);
        }

        match handle_has_identity(&env, &stranger) {
            GhostkeyResponse::IdentityPresence { usable, unusable } => {
                assert_eq!(
                    usable, 1,
                    "an ungranted caller learns only that an identity exists, never how many"
                );
                assert_eq!(unusable, 0);
            }
            other => panic!("expected IdentityPresence, got {other:?}"),
        }
    }

    /// An empty vault must still answer honestly, or an app that sends the
    /// user off to buy a ghostkey can never tell "you have none" from "I
    /// cannot see yours".
    #[test]
    fn has_identity_reports_an_empty_vault_as_empty() {
        let env = MemEnv::new();
        match handle_has_identity(&env, &webapp(0x03)) {
            GhostkeyResponse::IdentityPresence { usable, unusable } => {
                assert_eq!((usable, unusable), (0, 0));
            }
            other => panic!("expected IdentityPresence, got {other:?}"),
        }
    }

    #[test]
    fn scoped_presence_reports_only_granted_slots() {
        let slots = [
            KeySlot {
                has_certificate: true,
                has_signing_key: true,
                caller_may_read: true,
            },
            KeySlot {
                has_certificate: true,
                has_signing_key: false,
                caller_may_read: true,
            },
            KeySlot {
                has_certificate: true,
                has_signing_key: true,
                caller_may_read: false,
            },
        ];
        assert_eq!(scoped_presence(&slots), (1, 1));
    }

    #[test]
    fn scoped_presence_saturates_for_a_caller_with_no_grants() {
        let slots = [
            KeySlot {
                has_certificate: true,
                has_signing_key: true,
                caller_may_read: false,
            },
            KeySlot {
                has_certificate: true,
                has_signing_key: true,
                caller_may_read: false,
            },
            KeySlot {
                has_certificate: true,
                has_signing_key: false,
                caller_may_read: false,
            },
        ];
        assert_eq!(
            scoped_presence(&slots),
            (1, 1),
            "existence is disclosed, the count is not"
        );
    }

    #[test]
    fn scoped_presence_of_an_empty_vault_is_zero_for_anyone() {
        assert_eq!(scoped_presence(&[]), (0, 0));
    }

    /// A certificate whose chain does not reach the production Freenet master
    /// key must be refused. There is no longer any request field that can
    /// substitute a different trust root -- this pins the behaviour that
    /// removing `master_verifying_key_pem` is meant to guarantee.
    #[test]
    fn import_rejects_a_certificate_from_a_foreign_master_key() {
        let mut env = MemEnv::new();
        let (cert, sk) = test_ghostkey(100);
        let cert_pem = Armorable::to_armored_string(&cert).unwrap();
        let sk_pem = Armorable::to_armored_string(&sk).unwrap();

        let response = handle(
            &mut env,
            GhostkeyRequest::ImportGhostKey {
                certificate_pem: cert_pem,
                signing_key_pem: sk_pem,
            },
            &webapp(0x01),
        );
        assert!(
            matches!(response, GhostkeyResponse::Error { .. }),
            "a certificate signed by a throwaway master key must not import, got {response:?}"
        );
        assert!(
            load_index(&env).is_empty(),
            "a rejected import must leave nothing behind"
        );
    }

    #[test]
    fn rank_puts_the_most_valuable_key_first() {
        let ranked = rank_by_tier_desc(vec![
            ("cheap".to_string(), 5),
            ("rich".to_string(), 500),
            ("mid".to_string(), 20),
        ]);
        assert_eq!(ranked, vec!["rich", "mid", "cheap"]);
    }

    #[test]
    fn rank_is_stable_within_a_tier() {
        // Equal tiers keep index order, so the same vault always produces the
        // same picker -- a prompt whose buttons move between showings is a
        // prompt people click through without reading.
        let ranked = rank_by_tier_desc(vec![
            ("a".to_string(), 20),
            ("b".to_string(), 20),
            ("c".to_string(), 20),
        ]);
        assert_eq!(ranked, vec!["a", "b", "c"]);
    }

    #[test]
    fn rank_survives_truncation_without_dropping_the_best_key() {
        // The picker shows at most a handful of buttons. This is the case the
        // ranking exists for: an untiered key imported first must not push a
        // $500 key past the cutoff.
        let mut input: Vec<(String, u32)> = (0..12).map(|i| (format!("early{i}"), 0)).collect();
        input.push(("rich".to_string(), 500));
        let ranked = rank_by_tier_desc(input);
        assert_eq!(ranked[0], "rich");
    }

    #[test]
    fn tally_presence_empty_vault_reports_nothing() {
        assert_eq!(tally_presence(&[]), (0, 0));
    }

    #[test]
    fn tally_presence_splits_signable_from_half_present() {
        // Two complete keys, one certificate whose signing key is gone.
        let slots = [(true, true), (true, false), (true, true)];
        assert_eq!(tally_presence(&slots), (2, 1));
    }

    #[test]
    fn tally_presence_ignores_index_entries_with_no_certificate() {
        // A stale index entry must not be reported as an unusable identity --
        // there is nothing to recover, so nagging about it is pure noise.
        let slots = [(false, false), (false, true), (true, true)];
        assert_eq!(tally_presence(&slots), (1, 0));
    }

    #[test]
    fn tally_presence_all_half_present_is_not_reported_as_usable() {
        // The bug this guards: reporting `usable > 0` for a vault that can
        // list keys but sign with none would tell an app to go ahead and
        // then fail at signing time, with no way to explain why.
        let slots = [(true, false), (true, false)];
        assert_eq!(tally_presence(&slots), (0, 2));
    }

    #[test]
    fn test_verify_rejects_invalid_data() {
        let result = handle_verify(b"not valid cbor at all");
        match result {
            GhostkeyResponse::VerifyResult { valid, .. } => assert!(!valid),
            _ => panic!("expected VerifyResult"),
        }
    }
}
