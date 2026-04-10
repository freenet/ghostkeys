use dioxus::prelude::*;
use ghostkey_common::GhostKeyInfo;

#[component]
pub fn ImportDialog(on_close: EventHandler<()>, on_import: EventHandler<GhostKeyInfo>) -> Element {
    let mut cert_pem = use_signal(String::new);
    let mut sk_pem = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    let mut tab = use_signal(|| "paste"); // "paste" or "file"

    rsx! {
        div { class: "modal-overlay",
            onclick: move |_| on_close.call(()),

            div {
                class: "modal",
                onclick: move |e| e.stop_propagation(),

                h3 { "Import Ghostkey" }

                div { class: "tab-bar",
                    button {
                        class: if *tab.read() == "paste" { "tab active" } else { "tab" },
                        onclick: move |_| tab.set("paste"),
                        "Paste PEM"
                    }
                    button {
                        class: if *tab.read() == "file" { "tab active" } else { "tab" },
                        onclick: move |_| tab.set("file"),
                        "Upload Files"
                    }
                }

                if *tab.read() == "paste" {
                    div { class: "form-group",
                        label { "Certificate PEM" }
                        textarea {
                            class: "pem-input",
                            placeholder: "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\n...\n-----END GHOSTKEY_CERTIFICATE_V1-----",
                            rows: 6,
                            value: "{cert_pem}",
                            oninput: move |e| cert_pem.set(e.value()),
                        }
                    }

                    div { class: "form-group",
                        label { "Signing Key PEM" }
                        textarea {
                            class: "pem-input",
                            placeholder: "-----BEGIN ED25519_SIGNING_KEY-----\n...\n-----END ED25519_SIGNING_KEY-----",
                            rows: 6,
                            value: "{sk_pem}",
                            oninput: move |e| sk_pem.set(e.value()),
                        }
                    }
                } else {
                    div { class: "form-group",
                        label { "Certificate File" }
                        input {
                            r#type: "file",
                            accept: ".pem",
                            // File reading would need JS interop -- placeholder for now
                        }
                    }
                    div { class: "form-group",
                        label { "Signing Key File" }
                        input {
                            r#type: "file",
                            accept: ".pem",
                        }
                    }
                    p { class: "hint", "File upload will be connected in a future update." }
                }

                if let Some(err) = error_msg.read().as_ref() {
                    div { class: "error-msg", "{err}" }
                }

                div { class: "modal-actions",
                    button {
                        class: "btn",
                        onclick: move |_| on_close.call(()),
                        "Cancel"
                    }
                    button {
                        class: "btn btn-primary",
                        disabled: cert_pem.read().is_empty() || sk_pem.read().is_empty(),
                        onclick: move |_| {
                            let cert = cert_pem.read().clone();
                            let _sk = sk_pem.read().clone();

                            // In no-sync / example-data mode, fake the import
                            #[cfg(any(feature = "no-sync", feature = "example-data"))]
                            {
                                // Generate a fake fingerprint from the cert content
                                let hash = simple_hash(cert.as_bytes());
                                on_import.call(GhostKeyInfo {
                                    fingerprint: hash,
                                    label: None,
                                    delegate_info: "imported".into(),
                                });
                                return;
                            }

                            // Real mode: send to delegate via Freenet API
                            #[cfg(not(any(feature = "no-sync", feature = "example-data")))]
                            {
                                error_msg.set(Some("Delegate communication not yet implemented".into()));
                            }
                        },
                        "Import"
                    }
                }
            }
        }
    }
}

#[cfg(any(feature = "no-sync", feature = "example-data"))]
fn simple_hash(data: &[u8]) -> String {
    // Very simple hash for example mode -- not cryptographic
    let mut h: u64 = 0;
    for b in data {
        h = h.wrapping_mul(31).wrapping_add(*b as u64);
    }
    format!("{:x}", h)[..8].to_string()
}
