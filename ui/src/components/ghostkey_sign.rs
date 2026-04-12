use dioxus::prelude::*;
use ghostkey_common::{GhostkeyRequest, GhostkeyResponse};
use wasm_bindgen::JsCast;

use crate::api;
use crate::components::toast::{self, ToastKind};

#[component]
pub fn SignDialog(fingerprint: String, on_close: EventHandler<()>) -> Element {
    let mut message = use_signal(String::new);
    let mut signed_output = use_signal(|| None::<String>);
    let mut error_msg = use_signal(|| None::<String>);
    let mut signing = use_signal(|| false);
    let fp = fingerprint.clone();

    let has_result = signed_output.read().is_some();

    rsx! {
        div { class: "overlay",
            onclick: move |_| on_close.call(()),

            div {
                class: "dialog",
                onclick: move |e| e.stop_propagation(),

                div { class: "dialog-header",
                    h3 { class: "dialog-title",
                        if has_result { "Signed Message" } else { "Sign Message" }
                    }
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

                    if has_result {
                        // Result view: show the signed output with copy button
                        div { class: "field",
                            label { class: "field-label", "Original message" }
                            div { class: "result-message", "{message}" }
                        }

                        div { class: "field",
                            label { class: "field-label", "Signed output" }
                            textarea {
                                class: "pem-field result-field",
                                rows: 10,
                                readonly: true,
                                value: signed_output.read().as_deref().unwrap_or(""),
                            }
                        }

                        div { class: "dialog-footer",
                            button {
                                class: "action-btn",
                                onclick: move |_| {
                                    // Reset to sign another message
                                    signed_output.set(None);
                                    error_msg.set(None);
                                    message.set(String::new());
                                },
                                "Sign Another"
                            }
                            button {
                                class: "btn-glow",
                                onclick: move |_| {
                                    copy_to_clipboard(signed_output.read().as_deref().unwrap_or(""));
                                    toast::show("Copied to clipboard", ToastKind::Success);
                                },
                                "Copy"
                            }
                            button {
                                class: "action-btn",
                                onclick: move |_| on_close.call(()),
                                "Done"
                            }
                        }
                    } else {
                        // Input view: enter message and sign
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

                        div { class: "dialog-footer",
                            button {
                                class: "action-btn",
                                onclick: move |_| on_close.call(()),
                                "Cancel"
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

                                        spawn(async move {
                                            let resp = api::delegate::send_request(
                                                GhostkeyRequest::SignMessage {
                                                    fingerprint: fp,
                                                    message: msg.into_bytes(),
                                                },
                                            ).await;

                                            signing.set(false);

                                            match resp {
                                                Ok(GhostkeyResponse::SignResult { signature, certificate_pem, scoped_payload }) => {
                                                    let sig_pem = to_pem("GHOSTKEY_SIGNATURE", &signature);
                                                    let payload_pem = to_pem("GHOSTKEY_SIGNED_PAYLOAD", &scoped_payload);
                                                    signed_output.set(Some(format!(
                                                        "{sig_pem}\n{payload_pem}\n{certificate_pem}"
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
    }
}

fn copy_to_clipboard(text: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(window) = web_sys::window() {
            // Use the shell bridge for clipboard access (sandboxed iframe can't use navigator.clipboard)
            if let Ok(Some(parent)) = window.parent() {
                let msg = js_sys::Object::new();
                let _ = js_sys::Reflect::set(
                    &msg,
                    &"__freenet_shell__".into(),
                    &wasm_bindgen::JsValue::TRUE,
                );
                let _ = js_sys::Reflect::set(&msg, &"type".into(), &"clipboard".into());
                let _ = js_sys::Reflect::set(
                    &msg,
                    &"text".into(),
                    &wasm_bindgen::JsValue::from_str(text),
                );
                let _ = parent.post_message(&msg, "*");
            }
        }
    }
}

fn to_pem(label: &str, data: &[u8]) -> String {
    let b64 = base64_encode(data);
    // Wrap at 64 chars per line
    let wrapped: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----",
        wrapped.join("\n")
    )
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
