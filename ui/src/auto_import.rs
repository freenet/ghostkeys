use dioxus::logger::tracing::{error, info, warn};
use freenet_stdlib::prelude::ContractInstanceId;
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

use crate::api;
use crate::components::ghostkey_list;
use crate::components::toast::{self, ToastKind};

/// An import payload lifted out of the URL, waiting to be handed to the
/// delegate.
///
/// Parsing is deliberately separated from importing so the payload can be
/// taken off the URL *before* the vault starts talking to the node. It carries
/// a ghostkey that exists nowhere else yet -- the only other copy is on the
/// freenet.org success page, in a tab the user is about to close -- so a
/// startup failure must never drop it silently.
pub struct PendingImport {
    certificate_pem: String,
    signing_key_pem: String,
    /// Where the user was before they went off to buy this key, as a validated
    /// contract instance id. Offering the trip back is the whole point of the
    /// round trip being tolerable.
    return_to: Option<String>,
    /// Where *inside* that app, as a validated relative suffix (path and/or
    /// `#route`). `None` means the app's root. Only meaningful alongside
    /// `return_to`; the contract prefix is always synthesised from that id and
    /// never taken from the link.
    return_path: Option<String>,
}

/// Parse an import payload out of the URL hash, if there is one.
///
/// Fragment format: `#import=<base64_cert>.<base64_sk>`
/// Optional return target: `...&return_to=<base58_contract_key>`
/// Optional return route:  `...&return_path=<percent-encoded relative suffix>`
///
/// The hash is left in place on purpose: it is cleared only once the key is
/// safely in the delegate, so a reload can retry an import that did not land.
pub fn pending_import_from_url() -> Option<PendingImport> {
    let hash = get_hash()?;
    let hash = hash.strip_prefix('#').unwrap_or(&hash);
    parse_fragment(hash)
}

/// The parsing half of `pending_import_from_url`, split out so it can be
/// tested without a browser.
fn parse_fragment(hash: &str) -> Option<PendingImport> {
    // `&`-separated params, so `return_to` can be added without disturbing the
    // dot-separated positional shape of `import`'s own value.
    let mut import_value = None;
    let mut return_to_value = None;
    let mut return_path_value = None;
    for param in hash.split('&') {
        if let Some(v) = param.strip_prefix("import=") {
            import_value = Some(v);
        } else if let Some(v) = param.strip_prefix("return_to=") {
            return_to_value = Some(v);
        } else if let Some(v) = param.strip_prefix("return_path=") {
            return_path_value = Some(v);
        }
    }

    let payload = import_value?;
    let return_to = return_to_value.and_then(validated_return_to);
    // A path without a contract to hang it on is meaningless, and keeping one
    // would risk it being appended to some other app's id later.
    let return_path = return_to
        .as_ref()
        .and(return_path_value)
        .and_then(validated_return_path);

    info!("Auto-import detected in URL fragment");

    let parts: Vec<&str> = payload.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return reject("the link is malformed (expected 2 or 3 parts)");
    }
    // An empty part decodes successfully to an empty string, so without this
    // a degenerate link like `#import=.` would build a PendingImport carrying
    // no certificate and no key, and the user would get an obscure error from
    // the delegate instead of being told their link is malformed.
    if parts[..2].iter().any(|p| p.is_empty()) {
        return reject("the link is incomplete");
    }

    let Some(certificate_pem) = decode_base64(parts[0]) else {
        return reject("the certificate could not be decoded");
    };
    let Some(signing_key_pem) = decode_base64(parts[1]) else {
        return reject("the signing key could not be decoded");
    };

    // A third part used to be a master verifying key that the delegate would
    // trust in place of Freenet's own -- i.e. a link could tell the vault
    // which trust root to believe. It is ignored now, and the delegate has no
    // field to carry it: a certificate that only verifies under some other
    // master key is a certificate the vault should refuse. Links are still
    // accepted so an older purchase link keeps importing its (genuine) key.
    if parts.len() == 3 {
        warn!("Ignoring the master-verifying-key part of this import link: the certificate is always checked against Freenet's master key");
    }

    Some(PendingImport {
        certificate_pem,
        signing_key_pem,
        return_to,
        return_path,
    })
}

/// Accept a return target only if it is a well-formed contract instance id.
///
/// The value arrives in a URL the user was sent from an external site, and it
/// ends up in a link the vault renders. Parsing it with the same type the
/// gateway uses -- rather than pattern-matching the string -- means the vault
/// can only ever produce `/v1/contract/web/<valid key>/`, a same-origin path.
/// There is no shape of input that turns it into an off-site redirect.
fn validated_return_to(raw: &str) -> Option<String> {
    let id = match ContractInstanceId::from_bytes(raw) {
        Ok(id) => id,
        Err(e) => {
            warn!("Ignoring malformed return_to in import link: {e}");
            return None;
        }
    };

    // Parsing alone is not enough: `from_bytes` accepts a base58 string
    // shorter than 32 bytes and pads it, so a truncated value decodes to a
    // *different, valid-looking* contract id rather than failing. A clipped
    // link would then send the user confidently to somewhere they have never
    // been. Requiring the parse to round-trip rejects that, and every other
    // non-canonical encoding, without needing a base58 dependency here.
    let canonical = id.to_string();
    if canonical != raw {
        warn!("Ignoring non-canonical return_to in import link");
        return None;
    }
    Some(canonical)
}

/// Accept a relative suffix saying *where inside* the returning app to land.
///
/// The contract prefix is always synthesised from the validated id, so this
/// only ever decides what follows `/v1/contract/web/<id>/`. That still needs
/// guarding, because a relative href is resolved by the browser and a
/// `..` segment climbs out of the contract entirely.
///
/// The rules, in the order they have to happen:
///
/// 1. **Decode percent-encoding first.** It arrives encoded (it may contain
///    `#`, and it is already inside a fragment). Checking before decoding
///    would wave through `%2e%2e%2f`.
/// 2. **Then reject any remaining `%`.** The URL spec normalises `%2e` to `.`
///    when resolving dot segments, so a double-encoded `%252e%252e` decodes
///    once to `%2e%2e` and the *browser* would finish the job. Refusing a
///    surviving `%` closes that off without needing a decode-until-stable
///    loop. Real routes almost never need a literal percent.
/// 3. **Reject a leading `/`.** It would replace the whole path rather than
///    extend it, and `//host` would leave the origin.
/// 4. **Reject any `..` segment**, which is the only thing that can climb out.
/// 5. **Allowlist the characters**, so nothing can break out of the rendered
///    attribute or smuggle whitespace and control codes.
///
/// The gateway shell re-checks the `/v[12]/contract/web/{key}/` shape when it
/// handles the navigation, so a traversal has to get past both.
fn validated_return_path(raw: &str) -> Option<String> {
    const MAX_LEN: usize = 512;

    let decoded = percent_decode(raw)?;

    let reject = |why: &str| -> Option<String> {
        warn!("Ignoring return_path in import link: {why}");
        None
    };

    if decoded.is_empty() {
        return None; // Not an error; just means "the app's root".
    }
    if decoded.len() > MAX_LEN {
        return reject("too long");
    }
    if decoded.contains('%') {
        return reject("percent-encoding survived decoding (possible double-encoding)");
    }
    if decoded.starts_with('/') {
        return reject("absolute paths would replace the contract prefix");
    }
    // Check the path portion only: after `#` it is a client-side route and
    // cannot affect which resource is fetched.
    let path_part = decoded.split('#').next().unwrap_or("");
    if path_part.split('/').any(|seg| seg == "..") {
        return reject("`..` would climb out of the contract");
    }
    if !decoded.chars().all(is_allowed_return_path_char) {
        return reject("contains characters not allowed in a route");
    }

    Some(decoded)
}

/// Conservative allowlist for a return route: unreserved URL characters plus
/// the separators a real route needs, and nothing else.
///
/// Notably excludes `:`. A value like `https://evil.example` is not actually
/// dangerous here -- the rendered href starts with the synthesised
/// `/v1/contract/web/<id>/` prefix, so the browser resolves it as a
/// same-origin path rather than a redirect -- but it is meaningless, produces
/// a 404, and letting it through means the allowlist is not doing its job.
/// Real routes do not need a colon: `/user/:id` is a route *pattern*, and the
/// concrete route a user is actually on has the id substituted in.
///
/// Also excludes quotes, angle brackets, backslashes, whitespace and control
/// codes, so nothing can break out of the rendered attribute.
fn is_allowed_return_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '_' | '~' | '/' | '#' | '?' | '&' | '=' | '+' | '@' | ','
        )
}

/// Percent-decode a URL component. Returns `None` on a malformed escape, so a
/// mangled link is refused rather than silently half-decoded.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = *bytes.get(i + 1)?;
                let lo = *bytes.get(i + 2)?;
                let v = (hex_val(hi)? << 4) | hex_val(lo)?;
                out.push(v);
                i += 3;
            }
            // `+` is a form-encoding convention, not a URL-path one. Left as a
            // literal so a route containing one survives the round trip.
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Report a malformed import link.
///
/// These paths previously only logged to the console, so a user whose link was
/// mangled in transit just saw a vault that looked empty.
fn reject(reason: &str) -> Option<PendingImport> {
    error!("Rejecting import fragment: {reason}");
    toast::show(
        format!(
            "Could not import your ghostkey: {reason}. Use the Import button \
             and paste the key from your backup instead."
        ),
        ToastKind::Error,
    );
    None
}

/// Tell the user their key is still sitting in the URL, unimported.
///
/// The vault's startup sequence has several ways to fail before it can reach
/// the delegate, and every one of them used to drop a just-purchased key with
/// nothing but a console line to say so.
pub fn warn_not_imported() {
    toast::show(
        "Your ghostkey has NOT been imported: the vault could not reach your \
         Freenet node. Keep this tab open, check that your node is running, \
         then reload -- your key is still in this page's address.",
        ToastKind::Error,
    );
}

/// Hand a parsed payload to the delegate.
pub async fn import(pending: PendingImport) {
    info!(
        "Importing ghostkey from URL fragment (cert: {} bytes, sk: {} bytes)",
        pending.certificate_pem.len(),
        pending.signing_key_pem.len()
    );

    // Taken before the request moves the rest of the struct.
    let return_to = pending.return_to;
    let return_path = pending.return_path;

    let result = api::delegate::send_request(GhostkeyRequest::ImportGhostKey {
        certificate_pem: pending.certificate_pem,
        signing_key_pem: pending.signing_key_pem,
    })
    .await;

    match result {
        Ok(GhostkeyResponse::ImportResult {
            fingerprint,
            notary_info,
        }) => {
            info!("Auto-imported ghostkey: {fingerprint}");
            ghostkey_list::add_ghostkey(GhostKeyInfo {
                fingerprint: fingerprint.clone(),
                label: None,
                notary_info,
                verifying_key_bytes: None,
                // Optimistic placeholder; the delegate is the authority and
                // overwrites it on the next `ListGhostKeys`. A key that just
                // arrived via a purchase URL has no backup anywhere.
                backed_up: false,
            });
            clear_hash();
            toast::show(
                format!("Ghostkey {fingerprint} imported successfully"),
                ToastKind::Success,
            );
            // Only after the key is actually in the delegate. Offering the way
            // back while the import is still in doubt would walk the user away
            // from the one tab holding their key.
            if let Some(id) = return_to {
                ghostkey_list::offer_return_to(id, return_path);
            }
        }
        Ok(GhostkeyResponse::Error { message }) => {
            error!("Auto-import failed: {message}");
            toast::show(format!("Import failed: {message}"), ToastKind::Error);
        }
        Ok(other) => {
            error!(
                "Auto-import: unexpected response: {}",
                api::delegate::response_kind(&other)
            );
            toast::show("Import failed: unexpected response", ToastKind::Error);
        }
        Err(e) => {
            error!("Auto-import request failed: {e}");
            toast::show(format!("Import failed: {e}"), ToastKind::Error);
        }
    }
}

fn get_hash() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()?;
        let hash = window.location().hash().ok()?;
        if hash.is_empty() || hash == "#" {
            None
        } else {
            Some(hash)
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

/// Clear the URL hash from both the iframe and the shell page.
fn clear_hash() {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(window) = web_sys::window() {
            // Clear the iframe's own hash so get_hash() returns None on next check
            let _ = window.location().set_hash("");

            // Ask the shell page to clear the outer URL hash
            if let Some(parent) = window.parent().ok().flatten() {
                let msg = js_sys::Object::new();
                let _ = js_sys::Reflect::set(
                    &msg,
                    &wasm_bindgen::JsValue::from_str("__freenet_shell__"),
                    &wasm_bindgen::JsValue::TRUE,
                );
                let _ = js_sys::Reflect::set(
                    &msg,
                    &wasm_bindgen::JsValue::from_str("type"),
                    &wasm_bindgen::JsValue::from_str("hash"),
                );
                let _ = js_sys::Reflect::set(
                    &msg,
                    &wasm_bindgen::JsValue::from_str("hash"),
                    &wasm_bindgen::JsValue::from_str("#"),
                );
                let _ = parent.post_message(&msg, "*");
            }
        }
    }
}

fn decode_base64(input: &str) -> Option<String> {
    // URL-safe base64: replace - with + and _ with / before decoding
    let standard = input.replace('-', "+").replace('_', "/");

    // Add padding if needed
    let padded = match standard.len() % 4 {
        0 => standard,
        2 => format!("{standard}=="),
        3 => format!("{standard}="),
        // 4n+1 cannot be valid base64 -- no whole number of 6-bit groups
        // produces that length. This used to fall through unpadded and decode
        // to short garbage, so a truncated import link (a wrapped email, a
        // clipped copy-paste) surfaced as a confusing certificate error from
        // the delegate instead of the "this link is malformed, use your
        // backup" message the caller is waiting to show.
        _ => return None,
    };

    // Decode
    let bytes = base64_decode(&padded)?;
    String::from_utf8(bytes).ok()
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: [u8; 128] = {
        let mut t = [255u8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            t[(b'a' + i) as usize] = i + 26;
            i += 1;
        }
        let mut i = 0u8;
        while i < 10 {
            t[(b'0' + i) as usize] = i + 52;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let input = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in input {
        if b == b'=' {
            break;
        }
        if b >= 128 {
            return None;
        }
        let val = TABLE[b as usize];
        if val == 255 {
            if b == b'\n' || b == b'\r' || b == b' ' {
                continue;
            }
            return None;
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact shape `donation-success.js` produces: standard base64 with
    /// `+/` swapped for `-_` and trailing `=` stripped.
    fn url_safe(input: &str) -> String {
        #[allow(deprecated)]
        let standard = {
            // Tiny local encoder; the crate deliberately carries no base64
            // dependency, and the decoder under test is hand-rolled.
            const ALPHABET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let bytes = input.as_bytes();
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let b = [
                    chunk[0],
                    *chunk.get(1).unwrap_or(&0),
                    *chunk.get(2).unwrap_or(&0),
                ];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
                let idx = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
                let keep = chunk.len() + 1;
                for (i, ix) in idx.iter().enumerate() {
                    if i < keep {
                        out.push(ALPHABET[*ix as usize] as char);
                    }
                }
            }
            out
        };
        standard.replace('+', "-").replace('/', "_")
    }

    /// A real contract instance id, in the shape the gateway uses.
    const A_CONTRACT_ID: &str = "DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N";

    fn a_fragment(extra: &str) -> String {
        format!(
            "import={}.{}{extra}",
            url_safe("-----BEGIN CERT-----"),
            url_safe("-----BEGIN KEY-----")
        )
    }

    #[test]
    fn a_link_with_no_return_to_still_imports() {
        // The shape every link had before this existed. It must keep working
        // unchanged -- a purchase link in someone's open tab predates the
        // parameter entirely.
        let p = parse_fragment(&a_fragment("")).expect("import should parse");
        assert_eq!(p.certificate_pem, "-----BEGIN CERT-----");
        assert_eq!(p.return_to, None);
    }

    #[test]
    fn a_valid_return_to_is_carried_through() {
        let p = parse_fragment(&a_fragment(&format!("&return_to={A_CONTRACT_ID}")))
            .expect("import should parse");
        assert_eq!(p.return_to.as_deref(), Some(A_CONTRACT_ID));
    }

    #[test]
    fn return_to_order_does_not_matter() {
        let frag = format!("return_to={A_CONTRACT_ID}&{}", a_fragment(""));
        let p = parse_fragment(&frag).expect("import should parse");
        assert_eq!(p.return_to.as_deref(), Some(A_CONTRACT_ID));
        assert_eq!(p.certificate_pem, "-----BEGIN CERT-----");
    }

    /// The value arrives in a URL from an external site and ends up in a link
    /// the vault renders, so anything that is not a contract id must be
    /// dropped rather than passed through. A rejected `return_to` must never
    /// take the import down with it: the key is the irreplaceable part.
    #[test]
    fn a_return_to_that_is_not_a_contract_id_is_dropped_and_the_key_still_imports() {
        for hostile in [
            "https://evil.example/steal",
            "//evil.example",
            "javascript:alert(1)",
            "../../../v1/delegate/whatever",
            "DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N/../../..",
            "not base58 at all!!",
            // The fragment is never URL-decoded, so percent-encoding cannot
            // smuggle a path separator past the base58 check either.
            "..%2F..%2Fv1%2Fdelegate",
            "0OIl", // characters outside the base58 alphabet
            // Right alphabet, too short. `ContractInstanceId::from_bytes`
            // accepts this and pads it into a different, entirely valid id --
            // so a clipped link would otherwise send the user confidently to
            // somewhere they have never been.
            "DLog47hEsr",
            // Right alphabet, too long.
            "DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1NDLog47hEsrtu",
            "",
        ] {
            let p = parse_fragment(&a_fragment(&format!("&return_to={hostile}")))
                .unwrap_or_else(|| panic!("import must survive return_to={hostile:?}"));
            assert_eq!(p.return_to, None, "accepted a bad return_to: {hostile:?}");
        }
    }

    fn parse_with(return_to: &str, return_path: &str) -> Option<PendingImport> {
        parse_fragment(&a_fragment(&format!(
            "&return_to={return_to}&return_path={return_path}"
        )))
    }

    #[test]
    fn a_plain_route_is_carried_through() {
        let p = parse_with(A_CONTRACT_ID, "rooms%2Fabc%23%2Fthread%2F12").unwrap();
        assert_eq!(p.return_path.as_deref(), Some("rooms/abc#/thread/12"));
    }

    #[test]
    fn a_fragment_only_route_works() {
        let p = parse_with(A_CONTRACT_ID, "%23%2Fsettings").unwrap();
        assert_eq!(p.return_path.as_deref(), Some("#/settings"));
    }

    #[test]
    fn no_return_path_means_the_apps_root() {
        let p = parse_fragment(&a_fragment(&format!("&return_to={A_CONTRACT_ID}"))).unwrap();
        assert_eq!(p.return_path, None);
        assert_eq!(p.return_to.as_deref(), Some(A_CONTRACT_ID));
    }

    #[test]
    fn a_route_without_a_contract_is_dropped() {
        // A suffix with no id to hang it on is meaningless, and keeping one
        // risks it being appended to some other app's id later.
        let p = parse_fragment(&a_fragment("&return_path=rooms%2Fabc")).unwrap();
        assert_eq!(p.return_path, None);
        assert_eq!(p.return_to, None);
    }

    /// The only thing that can climb out of the contract is a `..` segment,
    /// and it has several disguises. Each must be refused, and none may take
    /// the import down with it.
    #[test]
    fn nothing_can_escape_the_contract_prefix() {
        let hostile = [
            ("..%2F..%2Fv1%2Fdelegate", "plain traversal"),
            ("%2e%2e%2F%2e%2e%2Fv1", "percent-encoded dots"),
            ("%252e%252e%252f", "double-encoded traversal"),
            (
                "rooms%2F..%2F..%2F..%2Fv1%2Fnode",
                "traversal after a real segment",
            ),
            ("%2Fv1%2Fdelegate%2Fx", "absolute path"),
            ("%2F%2Fevil.example", "protocol-relative"),
            ("https%3A%2F%2Fevil.example", "absolute URL"),
            ("javascript%3Aalert(1)", "javascript scheme"),
            ("a%22%20onload%3Dalert(1)", "attribute break-out"),
            ("a%3Cscript%3E", "angle brackets"),
            ("a%0d%0aX", "CRLF"),
            ("a%00b", "NUL"),
            ("a b", "raw space"),
            ("%GG", "malformed escape"),
        ];
        for (value, why) in hostile {
            let p = parse_with(A_CONTRACT_ID, value)
                .unwrap_or_else(|| panic!("import must survive return_path={why}"));
            assert_eq!(p.return_path, None, "accepted a hostile return_path: {why}");
            // The key is the irreplaceable part; a bad route must never cost it.
            assert_eq!(p.certificate_pem, "-----BEGIN CERT-----");
            assert_eq!(p.return_to.as_deref(), Some(A_CONTRACT_ID));
        }
    }

    /// Machine-generated sweep, wider than the hand-written cases. Anything
    /// that survives validation must resolve to a path still under the
    /// contract prefix once dot segments are normalised the way a browser
    /// normalises them.
    #[test]
    fn no_accepted_route_can_leave_the_contract_prefix() {
        let alphabet = [
            "a", "..", ".", "/", "%2e", "%2f", "%252e", "#", "?", "%00", "\\",
        ];
        let id = "DLog47hEsrtuGT4N5XCeMBG45m4n1aWM89tBZXue2E1N";
        let mut accepted = 0usize;
        // All 1-, 2- and 3-token combinations.
        for a in alphabet {
            for b in alphabet {
                for c in alphabet {
                    for candidate in [a.to_string(), format!("{a}{b}"), format!("{a}{b}{c}")] {
                        let Some(route) = validated_return_path(&candidate) else {
                            continue;
                        };
                        accepted += 1;
                        // Simulate the browser: resolve the href's path and
                        // normalise dot segments.
                        let href = format!("/v1/contract/web/{id}/{route}");
                        let path = href.split('#').next().unwrap_or("").to_string();
                        let mut stack: Vec<&str> = Vec::new();
                        for seg in path.split('/') {
                            match seg {
                                "" | "." => {}
                                ".." => {
                                    stack.pop();
                                }
                                other => stack.push(other),
                            }
                        }
                        let normalised = format!("/{}", stack.join("/"));
                        assert!(
                            normalised.starts_with(&format!("/v1/contract/web/{id}")),
                            "route {candidate:?} -> {route:?} escaped to {normalised}"
                        );
                    }
                }
            }
        }
        // A sweep that accepted nothing would pass vacuously.
        assert!(accepted > 0, "sweep accepted no routes at all -- vacuous");
    }

    #[test]
    fn an_over_long_route_is_refused() {
        let long = "a".repeat(600);
        let p = parse_with(A_CONTRACT_ID, &long).unwrap();
        assert_eq!(p.return_path, None);
    }

    /// `%2e` normalises to `.` during URL resolution, so the check has to
    /// happen after decoding, not before. This pins the ordering.
    #[test]
    fn decoding_happens_before_the_dot_check() {
        assert_eq!(percent_decode("%2e%2e%2f").as_deref(), Some("../"));
        assert_eq!(validated_return_path("%2e%2e%2f"), None);
    }

    #[test]
    fn percent_decode_refuses_a_malformed_escape() {
        assert_eq!(percent_decode("%"), None);
        assert_eq!(percent_decode("%2"), None);
        assert_eq!(percent_decode("%ZZ"), None);
        assert_eq!(percent_decode("ok%2Fthen").as_deref(), Some("ok/then"));
    }

    #[test]
    fn a_fragment_with_no_import_is_not_an_import() {
        // `return_to` alone is not a purchase link and must not be treated as
        // one, or a stray parameter would put a "return to app" banner in
        // front of a user who imported nothing.
        assert!(parse_fragment(&format!("return_to={A_CONTRACT_ID}")).is_none());
        assert!(parse_fragment("").is_none());
    }

    #[test]
    fn round_trips_a_pem_shaped_payload() {
        let pem = "-----BEGIN GHOSTKEY_CERTIFICATE_V1-----\nabc+def/ghi\n-----END-----";
        assert_eq!(decode_base64(&url_safe(pem)).as_deref(), Some(pem));
    }

    /// Every input length except 4n+1 is decodable; the encoder never emits
    /// 4n+1, so any input of that length has been damaged in transit.
    #[test]
    fn round_trips_every_payload_length() {
        for len in 1..40 {
            let payload = "x".repeat(len);
            assert_eq!(
                decode_base64(&url_safe(&payload)).as_deref(),
                Some(payload.as_str()),
                "failed at length {len}"
            );
        }
    }

    /// A clipped link must be refused, not decoded into short garbage. Before
    /// this, a 4n+1 payload fell through unpadded and produced a confusing
    /// certificate error from the delegate instead of a "use your backup"
    /// message.
    #[test]
    fn refuses_a_truncated_payload() {
        let full = url_safe("some ghostkey material here");
        // Largest 4n+1 length that fits, so this is a genuine prefix of a real
        // payload rather than a synthetic string.
        let clipped_len = ((full.len() - 1) / 4) * 4 + 1;
        let truncated: String = full.chars().take(clipped_len).collect();
        assert_eq!(truncated.len() % 4, 1, "test needs a 4n+1 length");
        assert_eq!(decode_base64(&truncated), None);
    }

    /// An empty part decodes fine to an empty string, so a degenerate link
    /// has to be caught before decoding or it produces a PendingImport with
    /// no key in it and an obscure delegate error downstream.
    #[test]
    fn an_empty_part_decodes_and_so_must_be_rejected_earlier() {
        assert_eq!(decode_base64("").as_deref(), Some(""));
    }

    #[test]
    fn refuses_characters_outside_the_alphabet() {
        assert_eq!(decode_base64("abcd!efg"), None);
        assert_eq!(decode_base64("ab*d"), None);
    }

    /// The URL-safe alphabet must map back to `+` and `/`, or any payload
    /// containing those bytes decodes wrongly.
    #[test]
    fn maps_the_url_safe_alphabet_back() {
        let with_both = decode_base64(&url_safe("??>")).unwrap();
        assert_eq!(with_both, "??>");
    }
}
