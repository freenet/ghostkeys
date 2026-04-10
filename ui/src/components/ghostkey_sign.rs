use dioxus::prelude::*;

#[component]
pub fn SignDialog(fingerprint: String, on_close: EventHandler<()>) -> Element {
    let mut message = use_signal(String::new);
    let mut result = use_signal(|| None::<String>);

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
                        disabled: message.read().is_empty(),
                        onclick: move |_| {
                            result.set(Some("[Signature output pending delegate connection]".into()));
                        },
                        "Sign"
                    }
                }
            }
        }
    }
}
