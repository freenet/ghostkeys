use dioxus::logger::tracing::{error, info, warn};
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

use crate::api;
use crate::components::ghostkey_list;
use crate::components::toast::{self, ToastKind};

/// An import payload lifted out of the URL, waiting to be handed to the
/// delegate.
///
/// Parsing is deliberately separated from importing so the payload can be
/// taken off the URL *before* the vault starts talking to the node. It carries
/// a ghostkey that exists nowhere else yet -- the only other copy is on the
/// freenet.org success page, in a tab the user is about to close -- so a
/// startup failure must never drop it silently.
pub struct PendingImport {
    certificate_pem: String,
    signing_key_pem: String,
    master_verifying_key_pem: Option<String>,
}

/// Parse an import payload out of the URL hash, if there is one.
///
/// Fragment format: `#import=<base64_cert>.<base64_sk>`
/// Optional master key: `#import=<base64_cert>.<base64_sk>.<base64_master_vk>`
///
/// The hash is left in place on purpose: it is cleared only once the key is
/// safely in the delegate, so a reload can retry an import that did not land.
pub fn pending_import_from_url() -> Option<PendingImport> {
    let hash = get_hash()?;
    let hash = hash.strip_prefix('#').unwrap_or(&hash);
    let payload = hash.strip_prefix("import=")?;

    info!("Auto-import detected in URL fragment");

    let parts: Vec<&str> = payload.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return reject("the link is malformed (expected 2 or 3 parts)");
    }

    let Some(certificate_pem) = decode_base64(parts[0]) else {
        return reject("the certificate could not be decoded");
    };
    let Some(signing_key_pem) = decode_base64(parts[1]) else {
        return reject("the signing key could not be decoded");
    };

    let master_verifying_key_pem = parts.get(2).copied().and_then(|part| {
        let decoded = decode_base64(part);
        if decoded.is_none() {
            warn!("Could not decode master verifying key from URL, using the default");
        }
        decoded
    });

    Some(PendingImport {
        certificate_pem,
        signing_key_pem,
        master_verifying_key_pem,
    })
}

/// Report a malformed import link.
///
/// These paths previously only logged to the console, so a user whose link was
/// mangled in transit just saw a vault that looked empty.
fn reject(reason: &str) -> Option<PendingImport> {
    error!("Rejecting import fragment: {reason}");
    toast::show(
        format!(
            "Could not import your ghostkey: {reason}. Use the Import button \
             and paste the key from your backup instead."
        ),
        ToastKind::Error,
    );
    None
}

/// Tell the user their key is still sitting in the URL, unimported.
///
/// The vault's startup sequence has several ways to fail before it can reach
/// the delegate, and every one of them used to drop a just-purchased key with
/// nothing but a console line to say so.
pub fn warn_not_imported() {
    toast::show(
        "Your ghostkey has NOT been imported: the vault could not reach your \
         Freenet node. Keep this tab open, check that your node is running, \
         then reload -- your key is still in this page's address.",
        ToastKind::Error,
    );
}

/// Hand a parsed payload to the delegate.
pub async fn import(pending: PendingImport) {
    info!(
        "Importing ghostkey from URL fragment (cert: {} bytes, sk: {} bytes)",
        pending.certificate_pem.len(),
        pending.signing_key_pem.len()
    );

    let result = api::delegate::send_request(GhostkeyRequest::ImportGhostKey {
        certificate_pem: pending.certificate_pem,
        signing_key_pem: pending.signing_key_pem,
        master_verifying_key_pem: pending.master_verifying_key_pem,
    })
    .await;

    match result {
        Ok(GhostkeyResponse::ImportResult {
            fingerprint,
            notary_info,
        }) => {
            info!("Auto-imported ghostkey: {fingerprint}");
            ghostkey_list::add_ghostkey(GhostKeyInfo {
                fingerprint: fingerprint.clone(),
                label: None,
                notary_info,
                verifying_key_bytes: None,
            });
            clear_hash();
            toast::show(
                format!("Ghostkey {fingerprint} imported successfully"),
                ToastKind::Success,
            );
        }
        Ok(GhostkeyResponse::Error { message }) => {
            error!("Auto-import failed: {message}");
            toast::show(format!("Import failed: {message}"), ToastKind::Error);
        }
        Ok(other) => {
            error!("Auto-import: unexpected response: {other:?}");
            toast::show("Import failed: unexpected response", ToastKind::Error);
        }
        Err(e) => {
            error!("Auto-import request failed: {e}");
            toast::show(format!("Import failed: {e}"), ToastKind::Error);
        }
    }
}

fn get_hash() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()?;
        let hash = window.location().hash().ok()?;
        if hash.is_empty() || hash == "#" {
            None
        } else {
            Some(hash)
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

/// Clear the URL hash from both the iframe and the shell page.
fn clear_hash() {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(window) = web_sys::window() {
            // Clear the iframe's own hash so get_hash() returns None on next check
            let _ = window.location().set_hash("");

            // Ask the shell page to clear the outer URL hash
            if let Some(parent) = window.parent().ok().flatten() {
                let msg = js_sys::Object::new();
                let _ = js_sys::Reflect::set(
                    &msg,
                    &wasm_bindgen::JsValue::from_str("__freenet_shell__"),
                    &wasm_bindgen::JsValue::TRUE,
                );
                let _ = js_sys::Reflect::set(
                    &msg,
                    &wasm_bindgen::JsValue::from_str("type"),
                    &wasm_bindgen::JsValue::from_str("hash"),
                );
                let _ = js_sys::Reflect::set(
                    &msg,
                    &wasm_bindgen::JsValue::from_str("hash"),
                    &wasm_bindgen::JsValue::from_str("#"),
                );
                let _ = parent.post_message(&msg, "*");
            }
        }
    }
}

fn decode_base64(input: &str) -> Option<String> {
    // URL-safe base64: replace - with + and _ with / before decoding
    let standard = input.replace('-', "+").replace('_', "/");

    // Add padding if needed
    let padded = match standard.len() % 4 {
        2 => format!("{standard}=="),
        3 => format!("{standard}="),
        _ => standard,
    };

    // Decode
    let bytes = base64_decode(&padded)?;
    String::from_utf8(bytes).ok()
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: [u8; 128] = {
        let mut t = [255u8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            t[(b'a' + i) as usize] = i + 26;
            i += 1;
        }
        let mut i = 0u8;
        while i < 10 {
            t[(b'0' + i) as usize] = i + 52;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let input = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in input {
        if b == b'=' {
            break;
        }
        if b >= 128 {
            return None;
        }
        let val = TABLE[b as usize];
        if val == 255 {
            if b == b'\n' || b == b'\r' || b == b' ' {
                continue;
            }
            return None;
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(out)
}
