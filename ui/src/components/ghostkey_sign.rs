use dioxus::prelude::*;
use ghostkey_common::{GhostkeyRequest, GhostkeyResponse};

use crate::api;

#[component]
pub fn SignDialog(fingerprint: String, on_close: EventHandler<()>) -> Element {
    let mut message = use_signal(String::new);
    let mut result = use_signal(|| None::<String>);
    let mut error_msg = use_signal(|| None::<String>);
    let mut signing = use_signal(|| false);
    let fp = fingerprint.clone();

    rsx! {
        div { class: "overlay",
            onclick: move |_| on_close.call(()),

            div {
                class: "dialog",
                onclick: move |e| e.stop_propagation(),

                div { class: "dialog-header",
                    h3 { class: "dialog-title", "Sign Message" }
                    button {
                        class: "close-btn",
                        onclick: move |_| on_close.call(()),
                        "\u{00d7}"
                    }
                }

                div { class: "dialog-body",
                    div { class: "sign-identity-badge",
                        span { class: "fp-label", "Signing as" }
                        code { class: "fp-value", "{fingerprint}" }
                    }

                    div { class: "field",
                        label { class: "field-label", "Message" }
                        textarea {
                            class: "message-field",
                            placeholder: "Enter message to sign...",
                            rows: 4,
                            value: "{message}",
                            oninput: move |e| message.set(e.value()),
                        }
                    }

                    if let Some(err) = error_msg.read().as_ref() {
                        div { class: "error-banner", "{err}" }
                    }

                    if let Some(res) = result.read().as_ref() {
                        div { class: "field",
                            label { class: "field-label", "Signature" }
                            textarea {
                                class: "pem-field result-field",
                                rows: 6,
                                readonly: true,
                                value: "{res}",
                            }
                        }
                    }
                }

                div { class: "dialog-footer",
                    button {
                        class: "action-btn",
                        onclick: move |_| on_close.call(()),
                        "Close"
                    }
                    button {
                        class: "btn-glow",
                        disabled: message.read().is_empty() || *signing.read(),
                        onclick: {
                            let fp = fp.clone();
                            move |_| {
                                let fp = fp.clone();
                                let msg = message.read().clone();
                                signing.set(true);
                                error_msg.set(None);
                                result.set(None);

                                spawn(async move {
                                    let resp = api::delegate::send_request(
                                        GhostkeyRequest::SignMessage {
                                            fingerprint: fp,
                                            message: msg.into_bytes(),
                                        },
                                    ).await;

                                    signing.set(false);

                                    match resp {
                                        Ok(GhostkeyResponse::SignResult { signature, certificate_pem, .. }) => {
                                            // Show base64-encoded signature + cert PEM
                                            let sig_b64 = base64_encode(&signature);
                                            result.set(Some(format!(
                                                "Signature: {sig_b64}\n\n{certificate_pem}"
                                            )));
                                        }
                                        Ok(GhostkeyResponse::PermissionDenied { .. }) => {
                                            error_msg.set(Some("Permission denied for this ghostkey".into()));
                                        }
                                        Ok(GhostkeyResponse::Error { message }) => {
                                            error_msg.set(Some(message));
                                        }
                                        Ok(other) => {
                                            error_msg.set(Some(format!("Unexpected: {other:?}")));
                                        }
                                        Err(e) => {
                                            error_msg.set(Some(e));
                                        }
                                    }
                                });
                            }
                        },
                        if *signing.read() { "Signing..." } else { "Sign" }
                    }
                }
            }
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}
