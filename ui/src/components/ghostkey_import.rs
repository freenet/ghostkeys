use dioxus::prelude::*;
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

use super::toast::{self, ToastKind};
use crate::api;

/// Extract the certificate and signing key PEM blocks from a combined paste.
///
/// The freenet.org success page delivers both blocks in a single textarea
/// (and single `.pem` download), concatenated with a blank line between
/// them (`${cert}\n\n${sk}`). Today the labels are
/// `GHOSTKEY_CERTIFICATE_V1` and `ED25519_SIGNING_KEY_V1`, but gklib uses
/// auto-generated labels with a `_V<n>` suffix that may bump over time, so
/// we classify by substring rather than by exact label.
///
/// Classification rules (applied in order; more specific substrings first
/// to avoid latent ambiguities like a hypothetical `SIGNED_CERTIFICATE`):
///
/// 1. Label contains `SIGNING_KEY` → signing key
/// 2. Label contains `CERTIFICATE` → certificate
/// 3. Anything else → counted as "extra" and causes the whole paste to be
///    rejected (prevents e.g. a `VERIFYING_KEY` master-key block sneaking
///    past — that belongs in the Advanced section, not the main paste).
///
/// The parser is order-independent and tolerates arbitrary leading/
/// trailing whitespace, blank lines between blocks, and CRLF line endings.
/// It does NOT validate PEM content beyond block framing; the caller
/// (delegate runtime) performs the real cryptographic validation.
///
/// Returns `(certificate_pem, signing_key_pem)` or an error message
/// suitable for display to the user.
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
        // A label containing a newline means a BEGIN line was never
        // terminated with `-----` and another BEGIN appeared later;
        // treat that as malformed rather than inventing a multi-line label.
        if label.contains('\n') || label.contains('\r') {
            return Err("Malformed PEM block: BEGIN line is missing its trailing '-----'".into());
        }
        let end_marker = format!("-----END {label}-----");
        let end_idx = match rest[begin_start..].find(&end_marker) {
            Some(i) => begin_start + i + end_marker.len(),
            None => {
                return Err(format!("Unterminated PEM block: missing {end_marker}"));
            }
        };
        let block = rest[begin_start..end_idx].to_string();
        let upper = label.to_ascii_uppercase();
        // Check SIGNING_KEY before CERTIFICATE so a future label containing
        // both substrings (e.g. a hypothetical signed-certificate variant)
        // is classified by the more specific term.
        if upper.contains("SIGNING_KEY") {
            if sk.is_some() {
                extras += 1;
            } else {
                sk = Some(block);
            }
        } else if upper.contains("CERTIFICATE") {
            if cert.is_some() {
                extras += 1;
            } else {
                cert = Some(block);
            }
        } else {
            extras += 1;
        }
        rest = &rest[end_idx..];
    }

    match (cert, sk) {
        (Some(c), Some(s)) if extras == 0 => Ok((c, s)),
        (Some(_), Some(_)) => Err(
            "Found extra PEM block(s) beyond the expected certificate + signing key. If you are pasting a master verifying key, use the Advanced section instead.".into()
        ),
        (None, _) => Err(
            "No certificate PEM block found. The paste should contain a BEGIN/END block whose label contains 'CERTIFICATE' (e.g. GHOSTKEY_CERTIFICATE_V1).".into()
        ),
        (_, None) => Err(
            "No signing key PEM block found. The paste should contain a BEGIN/END block whose label contains 'SIGNING_KEY' (e.g. ED25519_SIGNING_KEY_V1).".into()
        ),
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

    /// The literal format emitted by donation-success.js:243:
    /// `${armoredCertificate}\n\n${armoredSigningKey}` with no trailing
    /// newline. Locks in the contract with the issuance side.
    #[test]
    fn parses_donation_success_exact_format() {
        let combined = format!("{CERT}\n\n{SK}");
        let (c, s) = split_combined_pem(&combined).unwrap();
        assert_eq!(c, CERT);
        assert_eq!(s, SK);
    }

    /// Windows browsers and many password managers normalise textarea
    /// content to CRLF. The byte-offset-based parser should handle it.
    #[test]
    fn parses_crlf_line_endings() {
        let cert_crlf = CERT.replace('\n', "\r\n");
        let sk_crlf = SK.replace('\n', "\r\n");
        let combined = format!("{cert_crlf}\r\n\r\n{sk_crlf}\r\n");
        let (c, s) = split_combined_pem(&combined).unwrap();
        assert_eq!(c, cert_crlf);
        assert_eq!(s, sk_crlf);
    }

    #[test]
    fn tolerates_whitespace_around_blocks() {
        let combined = format!("   \n{CERT}\n   \n\n{SK}\n\n\n");
        assert!(split_combined_pem(&combined).is_ok());
    }

    /// Single newline between blocks (no blank line separator). Not what
    /// the success page emits, but users may reformat. Should still parse.
    #[test]
    fn tolerates_single_newline_between_blocks() {
        let combined = format!("{CERT}\n{SK}");
        assert!(split_combined_pem(&combined).is_ok());
    }

    #[test]
    fn rejects_missing_signing_key() {
        let err = split_combined_pem(CERT).unwrap_err();
        assert!(err.to_lowercase().contains("signing key"));
    }

    #[test]
    fn rejects_missing_certificate() {
        let err = split_combined_pem(SK).unwrap_err();
        assert!(err.to_lowercase().contains("certificate"));
    }

    /// A master verifying key pasted into the main box is rejected as
    /// an extra block, not silently misclassified.
    #[test]
    fn rejects_verifying_key_as_extra_block() {
        let vk = "-----BEGIN VERIFYING_KEY_V1-----\nCCCC\n-----END VERIFYING_KEY_V1-----";
        let combined = format!("{CERT}\n\n{SK}\n\n{vk}\n");
        let err = split_combined_pem(&combined).unwrap_err();
        assert!(err.to_lowercase().contains("extra"));
    }

    /// A paste of ONLY a verifying key (no cert, no sk) should report
    /// the missing certificate, not silently "extra block".
    #[test]
    fn rejects_verifying_key_only_with_missing_cert_message() {
        let vk = "-----BEGIN VERIFYING_KEY_V1-----\nCCCC\n-----END VERIFYING_KEY_V1-----";
        let err = split_combined_pem(vk).unwrap_err();
        assert!(err.to_lowercase().contains("certificate"));
    }

    #[test]
    fn rejects_unterminated_block() {
        let bad = "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\nAAAA\n";
        assert!(split_combined_pem(bad).is_err());
    }

    /// BEGIN line missing its trailing `-----` should be rejected cleanly
    /// rather than interpreted as a multi-line label.
    #[test]
    fn rejects_malformed_begin_line() {
        let bad = "-----BEGIN GHOSTKEY_CERTIFICATE_V1\nAAAA\n-----END GHOSTKEY_CERTIFICATE_V1-----";
        assert!(split_combined_pem(bad).is_err());
    }

    /// Labels are uppercased before classification, so mixed-case labels
    /// still parse (PEM is conventionally uppercase but we're lenient).
    #[test]
    fn parses_mixed_case_labels() {
        let cert =
            "-----BEGIN Ghostkey_Certificate_V1-----\nAAAA\n-----END Ghostkey_Certificate_V1-----";
        let sk =
            "-----BEGIN Ed25519_Signing_Key_V1-----\nBBBB\n-----END Ed25519_Signing_Key_V1-----";
        let combined = format!("{cert}\n\n{sk}");
        assert!(split_combined_pem(&combined).is_ok());
    }

    /// SIGNING_KEY check runs before CERTIFICATE check, so a hypothetical
    /// label like `SIGNED_CERTIFICATE` would classify as CERTIFICATE (no
    /// `SIGNING_KEY` substring) rather than as signing key. Pin this.
    #[test]
    fn tie_breaks_signing_key_before_certificate() {
        // `SIGNING_KEY_CERTIFICATE` would be ambiguous; the more specific
        // `SIGNING_KEY` substring wins because it's checked first.
        let ambiguous = "-----BEGIN SIGNING_KEY_CERTIFICATE_V1-----\nAAAA\n-----END SIGNING_KEY_CERTIFICATE_V1-----";
        let real_cert =
            "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\nBBBB\n-----END GHOSTKEY_CERTIFICATE_V1-----";
        // `ambiguous` should be classified as SK, `real_cert` as cert.
        let combined = format!("{ambiguous}\n\n{real_cert}");
        let (c, s) = split_combined_pem(&combined).unwrap();
        assert_eq!(c, real_cert);
        assert_eq!(s, ambiguous);
    }

    #[test]
    fn rejects_blank_input() {
        // Blank input hits the "no certificate" arm (no BEGIN markers).
        // The UI layer short-circuits before calling this, but pin the
        // behaviour in case that changes.
        assert!(split_combined_pem("").is_err());
        assert!(split_combined_pem("   \n\n  \n").is_err());
    }
}

#[component]
pub fn ImportDialog(on_close: EventHandler<()>, on_import: EventHandler<GhostKeyInfo>) -> Element {
    let mut combined_pem = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    let mut importing = use_signal(|| false);
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

                div { class: "dialog-body",
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
                                            verifying_key_bytes: None,
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
