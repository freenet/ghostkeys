use dioxus::prelude::*;
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

use crate::api;

#[component]
pub fn ImportDialog(on_close: EventHandler<()>, on_import: EventHandler<GhostKeyInfo>) -> Element {
    let mut cert_pem = use_signal(String::new);
    let mut sk_pem = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    let mut importing = use_signal(|| false);
    let mut tab = use_signal(|| "paste");
    let mut show_advanced = use_signal(|| false);
    let mut master_vk_pem = use_signal(String::new);

    rsx! {
        div { class: "overlay",
            onclick: move |_| on_close.call(()),

            div {
                class: "dialog",
                onclick: move |e| e.stop_propagation(),

                div { class: "dialog-header",
                    h3 { class: "dialog-title", "Import Identity" }
                    button {
                        class: "close-btn",
                        onclick: move |_| on_close.call(()),
                        "\u{00d7}"
                    }
                }

                div { class: "tab-strip",
                    button {
                        class: if *tab.read() == "paste" { "tab-btn active" } else { "tab-btn" },
                        onclick: move |_| tab.set("paste"),
                        "Paste PEM"
                    }
                    button {
                        class: if *tab.read() == "file" { "tab-btn active" } else { "tab-btn" },
                        onclick: move |_| tab.set("file"),
                        "Upload"
                    }
                }

                div { class: "dialog-body",
                    if *tab.read() == "paste" {
                        div { class: "field",
                            label { class: "field-label", "Certificate" }
                            textarea {
                                class: "pem-field",
                                placeholder: "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----",
                                rows: 5,
                                value: "{cert_pem}",
                                oninput: move |e| cert_pem.set(e.value()),
                            }
                        }
                        div { class: "field",
                            label { class: "field-label", "Signing Key" }
                            textarea {
                                class: "pem-field",
                                placeholder: "-----BEGIN ED25519_SIGNING_KEY-----",
                                rows: 5,
                                value: "{sk_pem}",
                                oninput: move |e| sk_pem.set(e.value()),
                            }
                        }
                    } else {
                        div { class: "field",
                            label { class: "field-label", "Certificate File" }
                            div { class: "file-drop",
                                input { r#type: "file", accept: ".pem" }
                                p { "Drop .pem file or click to browse" }
                            }
                        }
                        div { class: "field",
                            label { class: "field-label", "Signing Key File" }
                            div { class: "file-drop",
                                input { r#type: "file", accept: ".pem" }
                                p { "Drop .pem file or click to browse" }
                            }
                        }
                    }

                    button {
                        class: "tab-btn",
                        onclick: move |_| show_advanced.set(!show_advanced()),
                        if *show_advanced.read() { "Hide Advanced" } else { "Advanced..." }
                    }

                    if *show_advanced.read() {
                        div { class: "field",
                            label { class: "field-label", "Master Verifying Key (optional, for testing)" }
                            textarea {
                                class: "pem-field",
                                placeholder: "-----BEGIN VERIFYING_KEY_V1-----\nLeave empty for production Freenet master key",
                                rows: 3,
                                value: "{master_vk_pem}",
                                oninput: move |e| master_vk_pem.set(e.value()),
                            }
                        }
                    }

                    if let Some(err) = error_msg.read().as_ref() {
                        div { class: "error-banner", "{err}" }
                    }
                }

                div { class: "dialog-footer",
                    button {
                        class: "action-btn",
                        onclick: move |_| on_close.call(()),
                        "Cancel"
                    }
                    button {
                        class: "btn-glow",
                        disabled: cert_pem.read().is_empty() || sk_pem.read().is_empty() || *importing.read(),
                        onclick: move |_| {
                            let cert = cert_pem.read().clone();
                            let sk = sk_pem.read().clone();
                            let mvk = master_vk_pem.read().clone();
                            let mvk_opt = if mvk.trim().is_empty() { None } else { Some(mvk) };
                            importing.set(true);
                            error_msg.set(None);

                            spawn(async move {
                                let result = api::delegate::send_request(
                                    GhostkeyRequest::ImportGhostKey {
                                        certificate_pem: cert,
                                        signing_key_pem: sk,
                                        master_verifying_key_pem: mvk_opt,
                                    },
                                ).await;

                                importing.set(false);

                                match result {
                                    Ok(GhostkeyResponse::ImportResult { fingerprint, delegate_info }) => {
                                        on_import.call(GhostKeyInfo {
                                            fingerprint,
                                            label: None,
                                            delegate_info,
                                        });
                                    }
                                    Ok(GhostkeyResponse::Error { message }) => {
                                        error_msg.set(Some(message));
                                    }
                                    Ok(other) => {
                                        error_msg.set(Some(format!("Unexpected response: {other:?}")));
                                    }
                                    Err(e) => {
                                        error_msg.set(Some(e));
                                    }
                                }
                            });
                        },
                        if *importing.read() { "Importing..." } else { "Import Identity" }
                    }
                }
            }
        }
    }
}
