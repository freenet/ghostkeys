use dioxus::logger::tracing::{error, info, warn};
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

use crate::api;
use crate::components::ghostkey_list::GHOSTKEYS;

/// Check the URL hash fragment for an import payload and auto-import if found.
///
/// Fragment format: `#import=<base64_cert>.<base64_sk>`
/// Optional master key: `#import=<base64_cert>.<base64_sk>.<base64_master_vk>`
///
/// After successful import, the hash is cleared to prevent re-import on reload.
pub async fn check_and_import() {
    let hash = match get_hash() {
        Some(h) => h,
        None => return,
    };

    // Strip the leading '#'
    let hash = hash.strip_prefix('#').unwrap_or(&hash);

    // Check for import= prefix
    let payload = match hash.strip_prefix("import=") {
        Some(p) => p,
        None => return,
    };

    info!("Auto-import detected in URL fragment");

    // Split on '.' separator
    let parts: Vec<&str> = payload.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        warn!("Invalid import fragment: expected 2 or 3 dot-separated base64 parts");
        return;
    }

    // Decode base64
    let cert_pem = match decode_base64(parts[0]) {
        Some(s) => s,
        None => {
            error!("Failed to decode certificate from URL fragment");
            return;
        }
    };

    let sk_pem = match decode_base64(parts[1]) {
        Some(s) => s,
        None => {
            error!("Failed to decode signing key from URL fragment");
            return;
        }
    };

    let master_vk_pem = if parts.len() == 3 {
        match decode_base64(parts[2]) {
            Some(s) => Some(s),
            None => {
                warn!("Failed to decode master verifying key from URL fragment, using default");
                None
            }
        }
    } else {
        None
    };

    info!(
        "Importing ghostkey from URL fragment (cert: {} bytes, sk: {} bytes)",
        cert_pem.len(),
        sk_pem.len()
    );

    // Send import request to delegate
    let result = api::delegate::send_request(GhostkeyRequest::ImportGhostKey {
        certificate_pem: cert_pem,
        signing_key_pem: sk_pem,
        master_verifying_key_pem: master_vk_pem,
    })
    .await;

    match result {
        Ok(GhostkeyResponse::ImportResult {
            fingerprint,
            delegate_info,
        }) => {
            info!("Auto-imported ghostkey: {fingerprint}");
            GHOSTKEYS.write().push(GhostKeyInfo {
                fingerprint,
                label: None,
                delegate_info,
            });
            // Clear the hash to prevent re-import on reload
            clear_hash();
        }
        Ok(GhostkeyResponse::Error { message }) => {
            error!("Auto-import failed: {message}");
        }
        Ok(other) => {
            error!("Auto-import: unexpected response: {other:?}");
        }
        Err(e) => {
            error!("Auto-import request failed: {e}");
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

fn clear_hash() {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(window) = web_sys::window() {
            if let Some(history) = window.history().ok() {
                let _ = history.replace_state_with_url(
                    &wasm_bindgen::JsValue::NULL,
                    "",
                    Some(&window.location().pathname().unwrap_or_default()),
                );
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
            // Skip whitespace
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
