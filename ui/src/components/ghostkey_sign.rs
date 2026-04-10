use dioxus::prelude::*;

#[component]
pub fn SignDialog(fingerprint: String, on_close: EventHandler<()>) -> Element {
    let mut message = use_signal(String::new);
    let mut result = use_signal(|| None::<String>);

    rsx! {
        div { class: "modal-overlay",
            onclick: move |_| on_close.call(()),

            div {
                class: "modal",
                onclick: move |e| e.stop_propagation(),

                h3 { "Sign Message" }
                p { class: "hint",
                    "Signing with ghostkey {fingerprint}"
                }

                div { class: "form-group",
                    label { "Message" }
                    textarea {
                        class: "message-input",
                        placeholder: "Enter message to sign...",
                        rows: 4,
                        value: "{message}",
                        oninput: move |e| message.set(e.value()),
                    }
                }

                if let Some(res) = result.read().as_ref() {
                    div { class: "form-group",
                        label { "Signed Result" }
                        textarea {
                            class: "pem-input",
                            rows: 8,
                            readonly: true,
                            value: "{res}",
                        }
                    }
                }

                div { class: "modal-actions",
                    button {
                        class: "btn",
                        onclick: move |_| on_close.call(()),
                        "Close"
                    }
                    button {
                        class: "btn btn-primary",
                        disabled: message.read().is_empty(),
                        onclick: move |_| {
                            // Placeholder -- will send SignMessage to delegate
                            result.set(Some("[Signature will appear here when delegate is connected]".into()));
                        },
                        "Sign"
                    }
                }
            }
        }
    }
}
