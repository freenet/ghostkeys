use dioxus::prelude::*;
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};
use wasm_bindgen::JsCast;

use super::ghostkey_import::ImportDialog;
use super::ghostkey_sign::SignDialog;

pub static GHOSTKEYS: GlobalSignal<Vec<GhostKeyInfo>> = GlobalSignal::new(|| {
    #[cfg(feature = "example-data")]
    {
        vec![
            GhostKeyInfo {
                fingerprint: "3xKm9Rvp".into(),
                label: Some("Trading Identity".into()),
                notary_info: "donation_amount:100".into(),
            },
            GhostKeyInfo {
                fingerprint: "7bNq2Wft".into(),
                label: Some("Chat Identity".into()),
                notary_info: "donation_amount:20".into(),
            },
            GhostKeyInfo {
                fingerprint: "Hv5sRe8x".into(),
                label: None,
                notary_info: "donation_amount:5".into(),
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
                // Serialize to JSON and trigger download
                let json = serde_json::to_string_pretty(&keys).unwrap_or_default();
                #[cfg(target_arch = "wasm32")]
                {
                    let blob = web_sys::Blob::new_with_str_sequence_and_options(
                        &js_sys::Array::of1(&wasm_bindgen::JsValue::from_str(&json)),
                        web_sys::BlobPropertyBag::new().type_("application/json"),
                    );
                    if let Ok(blob) = blob {
                        if let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) {
                            if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
                                if let Ok(a) = doc.create_element("a") {
                                    let _ = a.set_attribute("href", &url);
                                    let _ = a.set_attribute("download", "ghostkeys-backup.json");
                                    let a: web_sys::HtmlElement = a.unchecked_into();
                                    a.click();
                                    let _ = web_sys::Url::revoke_object_url(&url);
                                }
                            }
                        }
                    }
                }
                toast::show(
                    format!("Exported {} ghostkey(s)", keys.len()),
                    ToastKind::Success,
                );
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

#[component]
pub fn GhostKeyList() -> Element {
    let keys = GHOSTKEYS.read();
    let show_import = SHOW_IMPORT.read();
    let sign_fp = SIGN_FINGERPRINT.read();

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

            if keys.is_empty() {
                div { class: "empty-vault",
                    div { class: "empty-icon" }
                    p { class: "empty-title", "No identities yet" }
                    p { class: "empty-hint",
                        "Purchase a ghostkey at "
                        span { class: "link-text", "freenet.org" }
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
    if after.starts_with('"') {
        // String value
        let content = &after[1..];
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
    let tier_class = tier_level(&info.notary_info);
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

                div { class: "card-actions-row",
                    button {
                        class: "action-btn action-sign",
                        onclick: move |_| *SIGN_FINGERPRINT.write() = Some(fp_for_sign.clone()),
                        "Sign"
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
