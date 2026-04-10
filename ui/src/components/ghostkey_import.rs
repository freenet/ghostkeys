use dioxus::prelude::*;
use ghostkey_common::GhostKeyInfo;

#[component]
pub fn ImportDialog(on_close: EventHandler<()>, on_import: EventHandler<GhostKeyInfo>) -> Element {
    let mut cert_pem = use_signal(String::new);
    let mut sk_pem = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    let mut tab = use_signal(|| "paste");

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
                        disabled: cert_pem.read().is_empty() || sk_pem.read().is_empty(),
                        onclick: move |_| {
                            let cert = cert_pem.read().clone();
                            let _sk = sk_pem.read().clone();

                            #[cfg(any(feature = "no-sync", feature = "example-data"))]
                            {
                                let hash = simple_hash(cert.as_bytes());
                                on_import.call(GhostKeyInfo {
                                    fingerprint: hash,
                                    label: None,
                                    delegate_info: "imported".into(),
                                });
                                return;
                            }

                            #[cfg(not(any(feature = "no-sync", feature = "example-data")))]
                            {
                                error_msg.set(Some("Delegate communication not yet wired".into()));
                            }
                        },
                        "Import Identity"
                    }
                }
            }
        }
    }
}

#[cfg(any(feature = "no-sync", feature = "example-data"))]
fn simple_hash(data: &[u8]) -> String {
    let mut h: u64 = 0;
    for b in data {
        h = h.wrapping_mul(31).wrapping_add(*b as u64);
    }
    format!("{:x}", h)[..8].to_string()
}
