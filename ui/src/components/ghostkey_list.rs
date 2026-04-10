use dioxus::prelude::*;
use ghostkey_common::GhostKeyInfo;

use super::ghostkey_import::ImportDialog;
use super::ghostkey_sign::SignDialog;

static GHOSTKEYS: GlobalSignal<Vec<GhostKeyInfo>> = GlobalSignal::new(|| {
    #[cfg(feature = "example-data")]
    {
        vec![
            GhostKeyInfo {
                fingerprint: "3xKm9Rvp".into(),
                label: Some("Trading Identity".into()),
                delegate_info: "donation_amount:100".into(),
            },
            GhostKeyInfo {
                fingerprint: "7bNq2Wft".into(),
                label: Some("Chat Identity".into()),
                delegate_info: "donation_amount:20".into(),
            },
            GhostKeyInfo {
                fingerprint: "Hv5sRe8x".into(),
                label: None,
                delegate_info: "donation_amount:5".into(),
            },
        ]
    }
    #[cfg(not(feature = "example-data"))]
    {
        vec![]
    }
});

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
                button {
                    class: "btn-glow",
                    onclick: move |_| *SHOW_IMPORT.write() = true,
                    span { class: "btn-icon", "+" }
                    span { "Import" }
                }
            }

            if *show_import {
                ImportDialog {
                    on_close: move || *SHOW_IMPORT.write() = false,
                    on_import: move |info: GhostKeyInfo| {
                        GHOSTKEYS.write().push(info);
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

fn parse_tier(info: &str) -> String {
    if let Some(amount) = info.strip_prefix("donation_amount:") {
        format!("${amount}")
    } else {
        info.to_string()
    }
}

fn tier_level(info: &str) -> &'static str {
    match info
        .strip_prefix("donation_amount:")
        .and_then(|a| a.parse::<u32>().ok())
    {
        Some(100..) => "tier-high",
        Some(20..=99) => "tier-mid",
        Some(1..=19) => "tier-low",
        _ => "tier-unknown",
    }
}

#[component]
fn GhostKeyCard(info: GhostKeyInfo, index: usize) -> Element {
    let fp_for_sign = info.fingerprint.clone();
    let fp_for_delete = info.fingerprint.clone();
    let tier_class = tier_level(&info.delegate_info);
    let delay = format!("{}ms", index * 80);

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
                    div { class: "tier-pill",
                        "{parse_tier(&info.delegate_info)}"
                    }
                }

                div { class: "card-identity",
                    if let Some(label) = &info.label {
                        span { class: "identity-name", "{label}" }
                    } else {
                        span { class: "identity-name unnamed", "Unnamed identity" }
                    }
                }

                div { class: "card-actions-row",
                    button {
                        class: "action-btn action-sign",
                        onclick: move |_| *SIGN_FINGERPRINT.write() = Some(fp_for_sign.clone()),
                        "Sign"
                    }
                    button {
                        class: "action-btn action-delete",
                        onclick: move |_| {
                            GHOSTKEYS.write().retain(|k| k.fingerprint != fp_for_delete);
                        },
                        "Remove"
                    }
                }
            }
        }
    }
}
