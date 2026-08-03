use dioxus::prelude::*;
use ghostkey_common::{ExportedGhostKey, GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

use super::ghostkey_import::ImportDialog;
use super::ghostkey_sign::SignDialog;

/// Where a user with no identities goes to get one.
///
/// The empty state used to render "freenet.org" as a `<span>` styled to look
/// like a link, so the one exit from an empty vault was not clickable. Links
/// straight to the donation form rather than the explainer: someone reading
/// this has already decided they want a ghostkey.
const PURCHASE_URL: &str = "https://freenet.org/ghostkey/create/";

pub static GHOSTKEYS: GlobalSignal<Vec<GhostKeyInfo>> = GlobalSignal::new(|| {
    #[cfg(feature = "example-data")]
    {
        vec![
            GhostKeyInfo {
                fingerprint: "3xKm9Rvp".into(),
                label: Some("Trading Identity".into()),
                notary_info: "donation_amount:100".into(),
                verifying_key_bytes: None,
                backed_up: true,
            },
            GhostKeyInfo {
                fingerprint: "7bNq2Wft".into(),
                label: Some("Chat Identity".into()),
                notary_info: "donation_amount:20".into(),
                verifying_key_bytes: None,
                backed_up: false,
            },
            GhostKeyInfo {
                fingerprint: "Hv5sRe8x".into(),
                label: None,
                notary_info: "donation_amount:5".into(),
                verifying_key_bytes: None,
                backed_up: false,
            },
        ]
    }
    #[cfg(not(feature = "example-data"))]
    {
        vec![]
    }
});

/// Add a ghostkey to the list, deduplicating by fingerprint.
pub fn add_ghostkey(info: GhostKeyInfo) {
    let mut keys = GHOSTKEYS.write();
    if !keys.iter().any(|k| k.fingerprint == info.fingerprint) {
        keys.push(info);
    }
}

/// Hand `json` to the browser as a file download. Returns whether a download
/// was actually triggered.
///
/// The return value matters: `export_all` used to claim success even when no
/// file was written, and the backup marker must never be set for a backup the
/// user does not have.
#[cfg(target_arch = "wasm32")]
fn trigger_download(json: &str, filename: &str) -> bool {
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type("application/json");
    let Ok(blob) = web_sys::Blob::new_with_str_sequence_and_options(
        &js_sys::Array::of1(&wasm_bindgen::JsValue::from_str(json)),
        &bag,
    ) else {
        return false;
    };
    let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) else {
        return false;
    };
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
        let _ = web_sys::Url::revoke_object_url(&url);
        return false;
    };
    let Ok(a) = doc.create_element("a") else {
        let _ = web_sys::Url::revoke_object_url(&url);
        return false;
    };
    let _ = a.set_attribute("href", &url);
    let _ = a.set_attribute("download", filename);
    let a: web_sys::HtmlElement = a.unchecked_into();
    a.click();
    let _ = web_sys::Url::revoke_object_url(&url);
    true
}

/// Off wasm there is no browser to download into, so nothing is ever saved.
/// Saying so is what stops the caller marking keys as backed up.
#[cfg(not(target_arch = "wasm32"))]
fn trigger_download(_json: &str, _filename: &str) -> bool {
    false
}

/// Tell the delegate the user now holds a copy of these identities outside
/// the vault, and clear their reminders locally.
///
/// Only ever called after a download actually fired: a marker set for a
/// backup that was never written would silence the one warning standing
/// between the user and a lost key.
async fn mark_backed_up(fingerprints: Vec<String>) {
    for fp in fingerprints {
        let marked = matches!(
            crate::api::delegate::send_request(GhostkeyRequest::MarkBackedUp {
                fingerprint: fp.clone(),
            })
            .await,
            Ok(GhostkeyResponse::BackedUpMarked { .. })
        );
        // Mirror into the local list only on confirmation, so a failed write
        // leaves the reminder showing rather than hiding it until reload.
        if marked {
            let mut keys = GHOSTKEYS.write();
            if let Some(k) = keys.iter_mut().find(|k| k.fingerprint == fp) {
                k.backed_up = true;
            }
        }
    }
}

/// Download a single identity and record that it has been backed up.
fn export_one(fingerprint: String) {
    spawn(async move {
        use super::toast::{self, ToastKind};

        let result = crate::api::delegate::send_request(GhostkeyRequest::ExportGhostKey {
            fingerprint: fingerprint.clone(),
        })
        .await;

        match result {
            Ok(GhostkeyResponse::ExportResult {
                fingerprint,
                certificate_pem,
                signing_key_pem,
                label,
            }) => {
                // `ExportResult` does not carry the notary info, but
                // `ExportAllGhostKeys` does. Fill it from the listed card so a
                // single-key backup file is byte-identical in shape to an
                // entry in a full one -- a backup format that varies by which
                // button produced it is a trap for whatever reads it later.
                let notary_info = GHOSTKEYS
                    .read()
                    .iter()
                    .find(|k| k.fingerprint == fingerprint)
                    .map(|k| k.notary_info.clone())
                    .unwrap_or_default();
                let exported = ExportedGhostKey {
                    fingerprint: fingerprint.clone(),
                    certificate_pem,
                    signing_key_pem,
                    label,
                    notary_info,
                };
                let json = serde_json::to_string_pretty(&exported).unwrap_or_default();
                if trigger_download(&json, &format!("ghostkey-{fingerprint}.json")) {
                    toast::show("Backup saved", ToastKind::Success);
                    mark_backed_up(vec![fingerprint]).await;
                } else {
                    toast::show("Could not save the backup file", ToastKind::Error);
                }
            }
            Ok(GhostkeyResponse::Error { message }) => {
                toast::show(format!("Backup failed: {message}"), ToastKind::Error);
            }
            Err(e) => {
                toast::show(format!("Backup failed: {e}"), ToastKind::Error);
            }
            Ok(other) => {
                toast::show(
                    format!(
                        "Backup failed: unexpected response {}",
                        crate::api::delegate::response_kind(&other)
                    ),
                    ToastKind::Error,
                );
            }
        }
    });
}

fn export_all() {
    spawn(async {
        use super::toast::{self, ToastKind};

        let result = crate::api::delegate::send_request(GhostkeyRequest::ExportAllGhostKeys).await;

        match result {
            Ok(GhostkeyResponse::ExportAllResult { keys }) => {
                if keys.is_empty() {
                    toast::show("No ghostkeys to export", ToastKind::Info);
                    return;
                }
                let json = serde_json::to_string_pretty(&keys).unwrap_or_default();
                if trigger_download(&json, "ghostkeys-backup.json") {
                    toast::show(
                        format!("Exported {} ghostkey(s)", keys.len()),
                        ToastKind::Success,
                    );
                    mark_backed_up(keys.into_iter().map(|k| k.fingerprint).collect()).await;
                } else {
                    // Previously this reported success regardless, so a
                    // failed download looked like a completed backup.
                    toast::show("Could not save the backup file", ToastKind::Error);
                }
            }
            Ok(GhostkeyResponse::Error { message }) => {
                toast::show(format!("Export failed: {message}"), ToastKind::Error);
            }
            Err(e) => {
                toast::show(format!("Export failed: {e}"), ToastKind::Error);
            }
            _ => {}
        }
    });
}

fn test_permission_prompt() {
    spawn(async {
        use super::toast::{self, ToastKind};

        let keys = GHOSTKEYS.read();
        let fp = match keys.first() {
            Some(k) => k.fingerprint.clone(),
            None => {
                toast::show("No ghostkeys to test with", ToastKind::Error);
                return;
            }
        };
        drop(keys);

        toast::show("Sending test prompt request...", ToastKind::Info);

        let result = crate::api::delegate::send_request(GhostkeyRequest::TestPermissionPrompt {
            fingerprint: fp,
        })
        .await;

        match result {
            Ok(GhostkeyResponse::PermissionDenied { .. }) => {
                toast::show("Permission denied by user", ToastKind::Info);
            }
            Ok(GhostkeyResponse::Error { message }) if message == "Test prompt approved" => {
                toast::show("Permission prompt approved!", ToastKind::Success);
            }
            Ok(GhostkeyResponse::Error { message }) => {
                toast::show(format!("Error: {message}"), ToastKind::Error);
            }
            Err(e) => {
                toast::show(format!("Request failed: {e}"), ToastKind::Error);
            }
            _ => {
                toast::show("Unexpected response", ToastKind::Info);
            }
        }
    });
}

static SHOW_IMPORT: GlobalSignal<bool> = GlobalSignal::new(|| false);
static SIGN_FINGERPRINT: GlobalSignal<Option<String>> = GlobalSignal::new(|| None);
static DEFAULT_KEY: GlobalSignal<Option<String>> = GlobalSignal::new(|| None);

/// Identities whose certificate is present but whose signing key is gone.
///
/// `ListGhostKeys` never checks for the signing key, so these render as
/// perfectly healthy cards right up until the user tries to sign. Asking the
/// delegate directly is the only way the vault can tell.
static UNUSABLE_COUNT: GlobalSignal<usize> = GlobalSignal::new(|| {
    // Seeded under `example-data` so `cargo make dev` shows the warning state
    // too. Without it the only way to see this banner is to genuinely lose a
    // signing key, which is not something to reproduce on purpose.
    #[cfg(feature = "example-data")]
    {
        1
    }
    #[cfg(not(feature = "example-data"))]
    {
        0
    }
});

/// Ask the delegate whether any stored identity has lost its signing key.
pub fn load_identity_presence() {
    spawn(async {
        if let Ok(GhostkeyResponse::IdentityPresence { unusable, .. }) =
            crate::api::delegate::send_request(GhostkeyRequest::HasIdentity).await
        {
            *UNUSABLE_COUNT.write() = unusable;
        }
    });
}

/// Load the default key from the delegate on startup.
pub fn load_default_key() {
    spawn(async {
        if let Ok(GhostkeyResponse::DefaultKeyResult {
            fingerprint: Some(fp),
        }) = crate::api::delegate::send_request(GhostkeyRequest::GetDefaultKey).await
        {
            *DEFAULT_KEY.write() = Some(fp);
        }
    });
}

#[component]
pub fn GhostKeyList() -> Element {
    let keys = GHOSTKEYS.read();
    let show_import = SHOW_IMPORT.read();
    let sign_fp = SIGN_FINGERPRINT.read();
    let unusable = *UNUSABLE_COUNT.read();

    rsx! {
        section { class: "vault-section",
            div { class: "section-header",
                div { class: "section-title-group",
                    h2 { class: "section-title", "Identities" }
                    span { class: "key-count", "{keys.len()}" }
                }
                div { class: "header-actions",
                    button {
                        class: "action-btn",
                        style: "color: var(--warning); border-color: var(--warning);",
                        onclick: move |_| test_permission_prompt(),
                        "Test Prompt"
                    }
                    button {
                        class: "action-btn",
                        onclick: move |_| export_all(),
                        "Export All"
                    }
                    button {
                        class: "btn-glow",
                        onclick: move |_| *SHOW_IMPORT.write() = true,
                        span { class: "btn-icon", "+" }
                        span { "Import" }
                    }
                }
            }

            if *show_import {
                ImportDialog {
                    on_close: move || *SHOW_IMPORT.write() = false,
                    on_import: move |info: GhostKeyInfo| {
                        add_ghostkey(info);
                        *SHOW_IMPORT.write() = false;
                    },
                }
            }

            if let Some(fp) = sign_fp.as_ref() {
                SignDialog {
                    fingerprint: fp.clone(),
                    on_close: move || *SIGN_FINGERPRINT.write() = None,
                }
            }

            if unusable > 0 {
                div { class: "vault-warning",
                    strong {
                        if unusable == 1 {
                            "One identity can no longer sign."
                        } else {
                            "{unusable} identities can no longer sign."
                        }
                    }
                    if unusable == 1 {
                        " Its certificate is still here but the private key is gone, so it cannot be used or backed up. Re-import it from a backup to restore it."
                    } else {
                        " Their certificates are still here but the private keys are gone, so they cannot be used or backed up. Re-import them from a backup to restore them."
                    }
                }
            }

            if keys.is_empty() {
                div { class: "empty-vault",
                    div { class: "empty-icon" }
                    p { class: "empty-title", "No identities yet" }
                    p { class: "empty-hint",
                        "Ghostkeys are issued when you donate to Freenet. "
                        a {
                            class: "link-text",
                            href: PURCHASE_URL,
                            target: "_blank",
                            rel: "noopener",
                            "Get one at freenet.org"
                        }
                        ", then import it here."
                    }
                }
            } else {
                div { class: "identity-stack",
                    for (i, gk) in keys.iter().enumerate() {
                        GhostKeyCard { info: gk.clone(), index: i }
                    }
                }
            }
        }
    }
}

fn extract_json_field<'a>(info: &'a str, field: &str) -> Option<&'a str> {
    let key = format!("\"{}\":", field);
    let pos = info.find(&key)?;
    let after = &info[pos + key.len()..];
    let after = after.trim_start();
    if let Some(content) = after.strip_prefix('"') {
        // String value
        let end = content.find('"')?;
        Some(&content[..end])
    } else {
        // Numeric value
        let end = after.find(|c: char| !c.is_ascii_digit())?;
        Some(&after[..end])
    }
}

fn extract_amount(info: &str) -> Option<u32> {
    if info.starts_with('{') {
        extract_json_field(info, "amount").and_then(|s| s.parse().ok())
    } else {
        info.strip_prefix("donation_amount:")
            .and_then(|a| a.parse().ok())
    }
}

fn extract_date(info: &str) -> Option<String> {
    if info.starts_with('{') {
        extract_json_field(info, "delegate-key-created").and_then(|s| {
            let date_part = s.split(' ').next().unwrap_or(s);
            format_date(date_part)
        })
    } else {
        None
    }
}

/// Format "2024-08-13" as "13th August, 2024"
fn format_date(ymd: &str) -> Option<String> {
    let parts: Vec<&str> = ymd.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year = parts[0];
    let month: u32 = parts[1].parse().ok()?;
    let day: u32 = parts[2].parse().ok()?;

    let month_name = match month {
        1 => "January",
        2 => "February",
        3 => "March",
        4 => "April",
        5 => "May",
        6 => "June",
        7 => "July",
        8 => "August",
        9 => "September",
        10 => "October",
        11 => "November",
        12 => "December",
        _ => return None,
    };

    let suffix = match day {
        1 | 21 | 31 => "st",
        2 | 22 => "nd",
        3 | 23 => "rd",
        _ => "th",
    };

    Some(format!("{day}{suffix} {month_name}, {year}"))
}

fn parse_tier(info: &str) -> String {
    match extract_amount(info) {
        Some(amount) => format!("${amount}"),
        None => "donated".to_string(),
    }
}

fn tier_level(info: &str) -> &'static str {
    match extract_amount(info) {
        Some(100..) => "tier-high",
        Some(20..=99) => "tier-mid",
        Some(1..=19) => "tier-low",
        _ => "tier-unknown",
    }
}

#[component]
fn GhostKeyCard(info: GhostKeyInfo, index: usize) -> Element {
    let fp = info.fingerprint.clone();
    let fp_for_sign = info.fingerprint.clone();
    let fp_for_delete = info.fingerprint.clone();
    let fp_for_label = info.fingerprint.clone();
    let fp_for_default = info.fingerprint.clone();
    let fp_for_backup = info.fingerprint.clone();
    let tier_class = tier_level(&info.notary_info);
    let is_default = DEFAULT_KEY
        .read()
        .as_ref()
        .is_some_and(|dk| dk == &info.fingerprint);
    let delay = format!("{}ms", index * 80);
    let mut label_input = use_signal(|| info.label.clone().unwrap_or_default());
    let mut confirming_delete = use_signal(|| false);

    rsx! {
        div {
            class: "identity-card {tier_class}",
            style: "animation-delay: {delay}",

            div { class: "card-glow" }

            div { class: "card-inner",
                div { class: "card-top-row",
                    div { class: "fingerprint-group",
                        span { class: "fp-label", "ID" }
                        code { class: "fp-value", "{info.fingerprint}" }
                        if is_default {
                            span { class: "default-badge", "default" }
                        }
                    }
                    div { class: "card-meta",
                        if let Some(date) = extract_date(&info.notary_info) {
                            span { class: "meta-date", "tier est. {date}" }
                        }
                        div { class: "tier-pill",
                            "{parse_tier(&info.notary_info)}"
                        }
                    }
                }

                div { class: "card-identity",
                    input {
                        class: "label-input",
                        r#type: "text",
                        placeholder: "Name this identity...",
                        value: "{label_input}",
                        oninput: move |e| label_input.set(e.value()),
                        onkeydown: {
                            let fp = fp_for_label.clone();
                            move |e: KeyboardEvent| {
                                if e.key() == Key::Enter {
                                    e.prevent_default();
                                    // Blur the input to visually deselect
                                    #[cfg(target_arch = "wasm32")]
                                    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
                                        if let Some(el) = doc.active_element() {
                                            let _ = el.dyn_into::<web_sys::HtmlElement>().map(|el| el.blur());
                                        }
                                    }
                                    let fp = fp.clone();
                                    let new_label = label_input.read().clone();
                                    spawn(async move {
                                        let _ = crate::api::delegate::send_request(
                                            GhostkeyRequest::SetLabel {
                                                fingerprint: fp.clone(),
                                                label: new_label.clone(),
                                            },
                                        ).await;
                                        let mut keys = GHOSTKEYS.write();
                                        if let Some(k) = keys.iter_mut().find(|k| k.fingerprint == fp) {
                                            k.label = if new_label.is_empty() { None } else { Some(new_label) };
                                        }
                                    });
                                }
                            }
                        },
                        onblur: {
                            let fp = fp.clone();
                            move |_| {
                                let fp = fp.clone();
                                let new_label = label_input.read().clone();
                                spawn(async move {
                                    let _ = crate::api::delegate::send_request(
                                        GhostkeyRequest::SetLabel {
                                            fingerprint: fp.clone(),
                                            label: new_label.clone(),
                                        },
                                    ).await;
                                    let mut keys = GHOSTKEYS.write();
                                    if let Some(k) = keys.iter_mut().find(|k| k.fingerprint == fp) {
                                        k.label = if new_label.is_empty() { None } else { Some(new_label) };
                                    }
                                });
                            }
                        },
                    }
                }

                if !info.backed_up {
                    div { class: "backup-nag",
                        span { class: "backup-nag-text",
                            "Only this vault holds this key. Save a copy so a lost node does not lose the identity."
                        }
                        button {
                            class: "action-btn action-backup",
                            onclick: {
                                let fp = fp_for_backup.clone();
                                move |_| export_one(fp.clone())
                            },
                            "Back up"
                        }
                    }
                }

                div { class: "card-actions-row",
                    button {
                        class: "action-btn action-sign",
                        onclick: move |_| *SIGN_FINGERPRINT.write() = Some(fp_for_sign.clone()),
                        "Sign"
                    }
                    if !is_default {
                        button {
                            class: "action-btn",
                            onclick: {
                                let fp = fp_for_default.clone();
                                move |_| {
                                    let fp = fp.clone();
                                    spawn(async move {
                                        let _ = crate::api::delegate::send_request(
                                            GhostkeyRequest::SetDefaultKey { fingerprint: fp.clone() },
                                        ).await;
                                        *DEFAULT_KEY.write() = Some(fp);
                                    });
                                }
                            },
                            "Set Default"
                        }
                    }
                    if *confirming_delete.read() {
                        span { class: "confirm-prompt", "Delete this identity?" }
                        button {
                            class: "action-btn action-confirm-yes",
                            onclick: move |_| {
                                let fp = fp_for_delete.clone();
                                GHOSTKEYS.write().retain(|k| k.fingerprint != fp);
                                spawn(async move {
                                    let _ = crate::api::delegate::send_request(
                                        GhostkeyRequest::DeleteGhostKey { fingerprint: fp },
                                    ).await;
                                });
                            },
                            "Yes"
                        }
                        button {
                            class: "action-btn",
                            onclick: move |_| confirming_delete.set(false),
                            "No"
                        }
                    } else {
                        button {
                            class: "action-btn action-delete",
                            onclick: move |_| confirming_delete.set(true),
                            "Remove"
                        }
                    }
                }
            }
        }
    }
}
