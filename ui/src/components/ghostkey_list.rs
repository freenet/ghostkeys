use dioxus::prelude::*;
use ghostkey_common::GhostKeyInfo;

use super::ghostkey_import::ImportDialog;
use super::ghostkey_sign::SignDialog;

/// Global state: list of ghostkeys known to the UI.
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
        div { class: "ghostkey-panel",
            div { class: "panel-header",
                h2 { "Your Ghostkeys" }
                button {
                    class: "btn btn-primary",
                    onclick: move |_| *SHOW_IMPORT.write() = true,
                    "Import Ghostkey"
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
                div { class: "empty-state",
                    p { "No ghostkeys imported yet." }
                    p { class: "hint",
                        "Purchase a ghostkey at freenet.org, then import it here."
                    }
                }
            } else {
                div { class: "ghostkey-grid",
                    for gk in keys.iter() {
                        GhostKeyCard { info: gk.clone() }
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

#[component]
fn GhostKeyCard(info: GhostKeyInfo) -> Element {
    let fp_for_sign = info.fingerprint.clone();
    let fp_for_delete = info.fingerprint.clone();

    rsx! {
        div { class: "ghostkey-card",
            div { class: "card-header",
                span { class: "fingerprint", "{info.fingerprint}" }
                span { class: "tier-badge", "{parse_tier(&info.delegate_info)}" }
            }

            div { class: "card-body",
                if let Some(label) = &info.label {
                    p { class: "label", "{label}" }
                } else {
                    p { class: "label muted", "No label" }
                }
            }

            div { class: "card-actions",
                button {
                    class: "btn btn-sm",
                    onclick: move |_| *SIGN_FINGERPRINT.write() = Some(fp_for_sign.clone()),
                    "Sign"
                }
                button {
                    class: "btn btn-sm btn-danger",
                    onclick: move |_| {
                        GHOSTKEYS.write().retain(|k| k.fingerprint != fp_for_delete);
                    },
                    "Delete"
                }
            }
        }
    }
}
