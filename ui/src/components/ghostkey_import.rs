use dioxus::prelude::*;
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

use super::toast::{self, ToastKind};
use crate::api;

/// Extract the certificate and signing key PEM blocks from a combined paste.
///
/// The freenet.org success page delivers both blocks in a single textarea
/// (and single `.pem` download), concatenated with a blank line between them.
/// This parser accepts that format: any text that contains exactly one PEM
/// block whose label contains "CERT" and one whose label contains "SIGN".
///
/// Returns `(certificate_pem, signing_key_pem)` or an error message suitable
/// for display to the user.
pub(crate) fn split_combined_pem(input: &str) -> Result<(String, String), String> {
    let mut cert: Option<String> = None;
    let mut sk: Option<String> = None;
    let mut extras = 0usize;

    let mut rest = input;
    while let Some(begin_start) = rest.find("-----BEGIN ") {
        let after_begin = &rest[begin_start + "-----BEGIN ".len()..];
        let label_end = match after_begin.find("-----") {
            Some(i) => i,
            None => break,
        };
        let label = after_begin[..label_end].trim().to_string();
        let end_marker = format!("-----END {label}-----");
        let end_idx = match rest[begin_start..].find(&end_marker) {
            Some(i) => begin_start + i + end_marker.len(),
            None => {
                return Err(format!("Unterminated PEM block: missing {end_marker}"));
            }
        };
        let block = rest[begin_start..end_idx].to_string();
        let upper = label.to_ascii_uppercase();
        if upper.contains("CERT") {
            if cert.is_some() {
                extras += 1;
            } else {
                cert = Some(block);
            }
        } else if upper.contains("SIGN") {
            if sk.is_some() {
                extras += 1;
            } else {
                sk = Some(block);
            }
        } else {
            extras += 1;
        }
        rest = &rest[end_idx..];
    }

    match (cert, sk) {
        (Some(c), Some(s)) if extras == 0 => Ok((c, s)),
        (Some(_), Some(_)) => Err(format!(
            "Found extra PEM block(s) beyond the expected certificate + signing key"
        )),
        (None, _) => Err("No certificate PEM block found (expected a BEGIN/END block whose label contains 'CERT')".into()),
        (_, None) => Err("No signing key PEM block found (expected a BEGIN/END block whose label contains 'SIGN')".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::split_combined_pem;

    const CERT: &str =
        "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\nAAAA\n-----END GHOSTKEY_CERTIFICATE_V1-----";
    const SK: &str =
        "-----BEGIN ED25519_SIGNING_KEY_V1-----\nBBBB\n-----END ED25519_SIGNING_KEY_V1-----";

    #[test]
    fn parses_cert_then_signing_key() {
        let combined = format!("{CERT}\n\n{SK}\n");
        let (c, s) = split_combined_pem(&combined).unwrap();
        assert_eq!(c, CERT);
        assert_eq!(s, SK);
    }

    #[test]
    fn parses_signing_key_then_cert() {
        let combined = format!("{SK}\n\n{CERT}\n");
        let (c, s) = split_combined_pem(&combined).unwrap();
        assert_eq!(c, CERT);
        assert_eq!(s, SK);
    }

    #[test]
    fn tolerates_whitespace_around_blocks() {
        let combined = format!("   \n{CERT}\n   \n\n{SK}\n\n\n");
        assert!(split_combined_pem(&combined).is_ok());
    }

    #[test]
    fn rejects_missing_signing_key() {
        let err = split_combined_pem(CERT).unwrap_err();
        assert!(err.contains("signing key"));
    }

    #[test]
    fn rejects_missing_certificate() {
        let err = split_combined_pem(SK).unwrap_err();
        assert!(err.contains("certificate"));
    }

    #[test]
    fn rejects_extra_block() {
        let extra = "-----BEGIN VERIFYING_KEY_V1-----\nCCCC\n-----END VERIFYING_KEY_V1-----";
        let combined = format!("{CERT}\n\n{SK}\n\n{extra}\n");
        assert!(split_combined_pem(&combined).is_err());
    }

    #[test]
    fn rejects_unterminated_block() {
        let bad = "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\nAAAA\n";
        assert!(split_combined_pem(bad).is_err());
    }
}

#[component]
pub fn ImportDialog(on_close: EventHandler<()>, on_import: EventHandler<GhostKeyInfo>) -> Element {
    let mut combined_pem = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    let mut importing = use_signal(|| false);
    let mut tab = use_signal(|| "paste");
    let mut show_advanced = use_signal(|| false);
    let mut master_vk_pem = use_signal(String::new);

    let parsed = use_memo(move || {
        let text = combined_pem.read();
        if text.trim().is_empty() {
            None
        } else {
            Some(split_combined_pem(&text))
        }
    });
    let can_import = matches!(&*parsed.read(), Some(Ok(_)));
    let parse_err: Option<String> = match &*parsed.read() {
        Some(Err(e)) => Some(e.clone()),
        _ => None,
    };

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
                            label { class: "field-label", "Ghost Key (certificate + signing key)" }
                            textarea {
                                class: "pem-field",
                                placeholder: "Paste the full Ghost Key text from freenet.org here.\nIt should contain both the -----BEGIN GHOSTKEY_CERTIFICATE_V1----- block and the -----BEGIN ED25519_SIGNING_KEY_V1----- block.",
                                rows: 10,
                                value: "{combined_pem}",
                                oninput: move |e| combined_pem.set(e.value()),
                            }
                            if let Some(err) = parse_err.as_ref() {
                                if !combined_pem.read().trim().is_empty() {
                                    div { class: "error-banner", "{err}" }
                                }
                            }
                        }
                    } else {
                        div { class: "field",
                            label { class: "field-label", "Ghost Key File (freenet_ghost_key.pem)" }
                            div { class: "file-drop",
                                input { r#type: "file", accept: ".pem,text/plain" }
                                p { "Drop your freenet_ghost_key.pem file or click to browse" }
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
                        disabled: !can_import || *importing.read(),
                        onclick: move |_| {
                            let (cert, sk) = match split_combined_pem(&combined_pem.read()) {
                                Ok(pair) => pair,
                                Err(e) => {
                                    error_msg.set(Some(e));
                                    return;
                                }
                            };
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
                                    Ok(GhostkeyResponse::ImportResult { fingerprint, notary_info }) => {
                                        toast::show(format!("Ghostkey {fingerprint} imported"), ToastKind::Success);
                                        on_import.call(GhostKeyInfo {
                                            fingerprint,
                                            label: None,
                                            notary_info,
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
