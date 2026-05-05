#![allow(unexpected_cfgs)]

mod handlers;
mod logging;
mod permissions;

use freenet_stdlib::prelude::{
    delegate, ApplicationMessage, DelegateCtx, DelegateError, DelegateInterface,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, Parameters,
};

use ghostkey_common::{from_cbor, to_cbor, GhostkeyRequest, GhostkeyScope, SignatureRequestor};

/// State persisted in the delegate context while a user prompt is in flight.
#[derive(serde::Serialize, serde::Deserialize)]
enum PendingPrompt {
    /// The classic flow: a request named a specific fingerprint and the
    /// caller didn't have permission. After the user approves we grant
    /// `requestor` access (third-party scope set if the caller is not the
    /// vault) and replay `original_payload`.
    Fingerprint {
        request_id: u32,
        fingerprint: String,
        requestor: SignatureRequestor,
        original_payload: Vec<u8>,
    },
    /// `RequestAnyAccess`: the user picks a fingerprint from a button
    /// list. On approval we grant the third-party scope set for the
    /// chosen fingerprint and synthesise a one-element `GhostKeyList`
    /// reply -- no payload to replay because the original request didn't
    /// reference a specific key.
    AnyAccess {
        request_id: u32,
        requestor: SignatureRequestor,
        /// Index `i` in the user response maps to `fingerprints[i]`.
        /// The trailing button is the deny button and has no entry here.
        fingerprints: Vec<String>,
    },
}

pub struct GhostkeyDelegate;

#[delegate]
impl DelegateInterface for GhostkeyDelegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        match message {
            InboundDelegateMsg::ApplicationMessage(app_msg) => {
                if app_msg.processed {
                    return Err(DelegateError::Other(
                        "cannot process an already processed message".into(),
                    ));
                }

                let requestor = match origin {
                    Some(MessageOrigin::WebApp(contract_id)) => {
                        SignatureRequestor::WebApp(contract_id)
                    }
                    Some(MessageOrigin::Delegate(delegate_key)) => {
                        // stdlib 0.6 routes inter-delegate calls through
                        // MessageOrigin::Delegate(caller_key). Trust the
                        // runtime-attested caller identity for authorization.
                        SignatureRequestor::Delegate(delegate_key)
                    }
                    None => {
                        return Err(DelegateError::Other(
                            "missing message origin for application message".into(),
                        ));
                    }
                    // Required by `#[non_exhaustive]` on MessageOrigin.
                    // Reject unknown origin kinds rather than silently
                    // granting access under an ambiguous identity.
                    Some(_) => {
                        return Err(DelegateError::Other(
                            "unsupported message origin kind".into(),
                        ));
                    }
                };

                handle_request(ctx, &app_msg.payload, &requestor)
            }

            InboundDelegateMsg::DelegateMessage(del_msg) => {
                if del_msg.processed {
                    return Err(DelegateError::Other(
                        "cannot process an already processed message".into(),
                    ));
                }

                let requestor = SignatureRequestor::Delegate(del_msg.sender);
                handle_request(ctx, &del_msg.payload, &requestor)
            }

            InboundDelegateMsg::UserResponse(user_resp) => handle_user_response(ctx, &user_resp),

            other => {
                let msg_type = match &other {
                    InboundDelegateMsg::GetContractResponse(_) => "GetContractResponse",
                    InboundDelegateMsg::PutContractResponse(_) => "PutContractResponse",
                    InboundDelegateMsg::UpdateContractResponse(_) => "UpdateContractResponse",
                    InboundDelegateMsg::SubscribeContractResponse(_) => "SubscribeContractResponse",
                    InboundDelegateMsg::ContractNotification(_) => "ContractNotification",
                    _ => "Unknown",
                };
                Err(DelegateError::Other(format!(
                    "unexpected message type: {msg_type}"
                )))
            }
        }
    }
}

fn handle_request(
    ctx: &mut DelegateCtx,
    payload: &[u8],
    requestor: &SignatureRequestor,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let request: GhostkeyRequest = from_cbor(payload)
        .map_err(|e| DelegateError::Other(format!("deserialize request: {e}")))?;

    // TestPermissionPrompt always triggers the prompt.
    if let GhostkeyRequest::TestPermissionPrompt { ref fingerprint } = request {
        return request_user_permission(ctx, fingerprint, requestor, payload);
    }

    // RequestAnyAccess routes to a multi-key picker prompt rather than
    // the single-fingerprint flow. The caller doesn't know any
    // fingerprint yet -- the vault produces the choice.
    if matches!(request, GhostkeyRequest::RequestAnyAccess) {
        return request_any_access(ctx, requestor);
    }

    // Permission-sensitive operations check the appropriate scope.
    if let Some(scope) = required_scope(&request) {
        if let Some(fp) = get_fingerprint(&request) {
            if !permissions::has_scope(ctx, &fp, requestor, scope) {
                // Only fire a user prompt for scopes the third-party flow
                // can actually grant (`ReadPublic` and `Sign`). Higher
                // scopes (`Export`, `Delete`, `Admin`) are vault-only:
                // prompting for them would mislead the user into clicking
                // Allow on a request that the replay would still deny,
                // because `grant_third_party` never adds those scopes.
                if matches!(scope, GhostkeyScope::ReadPublic | GhostkeyScope::Sign) {
                    return request_user_permission(ctx, &fp, requestor, payload);
                }
                // Hard-deny without prompting. The user reaches these
                // operations through the vault, where the requestor is
                // already the vault and has the scope.
                return deny_immediately(&fp, requestor);
            }
        }
    }

    let response = handlers::handle(ctx, request, requestor);

    let response_bytes =
        to_cbor(&response).map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;

    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}

/// Emit a `PermissionDenied` response without firing a prompt. Used for
/// scopes that `RequestAnyAccess`'s third-party grant path cannot satisfy
/// (`Export`, `Delete`, `Admin`); prompting in those cases would mislead
/// the user, because the replayed handler would still deny the request.
fn deny_immediately(
    fingerprint: &str,
    requestor: &SignatureRequestor,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let response = ghostkey_common::GhostkeyResponse::PermissionDenied {
        fingerprint: fingerprint.to_string(),
        requestor: requestor.clone(),
    };
    let bytes =
        to_cbor(&response).map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(bytes),
    )])
}

/// Map a request to the scope it needs the caller to hold.
///
/// Requests that operate on a specific fingerprint return the scope they
/// need. Requests that don't (e.g. `ListGhostKeys`, which is filtered
/// per-key inside the handler) return `None`.
fn required_scope(request: &GhostkeyRequest) -> Option<GhostkeyScope> {
    match request {
        GhostkeyRequest::GetGhostKey { .. } | GhostkeyRequest::GetCertificate { .. } => {
            Some(GhostkeyScope::ReadPublic)
        }
        GhostkeyRequest::SignMessage { .. } => Some(GhostkeyScope::Sign),
        GhostkeyRequest::ExportGhostKey { .. } => Some(GhostkeyScope::Export),
        GhostkeyRequest::DeleteGhostKey { .. } | GhostkeyRequest::SetLabel { .. } => {
            Some(GhostkeyScope::Delete)
        }
        GhostkeyRequest::GrantPermission { .. } | GhostkeyRequest::RevokePermission { .. } => {
            Some(GhostkeyScope::Admin)
        }
        _ => None,
    }
}

/// Extract the fingerprint from a request, if applicable.
fn get_fingerprint(request: &GhostkeyRequest) -> Option<String> {
    match request {
        GhostkeyRequest::GetGhostKey { fingerprint }
        | GhostkeyRequest::GetCertificate { fingerprint }
        | GhostkeyRequest::SignMessage { fingerprint, .. }
        | GhostkeyRequest::DeleteGhostKey { fingerprint }
        | GhostkeyRequest::SetLabel { fingerprint, .. }
        | GhostkeyRequest::ExportGhostKey { fingerprint }
        | GhostkeyRequest::GrantPermission { fingerprint, .. }
        | GhostkeyRequest::RevokePermission { fingerprint, .. } => Some(fingerprint.clone()),
        _ => None,
    }
}

/// Render the runtime-attested requestor as a short human-readable label.
/// The string is only ever rendered alongside the full hash in the prompt
/// UI; both come from runtime context, never from the delegate's payload.
fn requestor_short_label(requestor: &SignatureRequestor) -> String {
    match requestor {
        SignatureRequestor::WebApp(id) => {
            let s = id.to_string();
            let short = &s[..8.min(s.len())];
            format!("A Freenet application ({short}...)")
        }
        SignatureRequestor::Delegate(key) => {
            let s = key.encode();
            let short = &s[..8.min(s.len())];
            format!("A Freenet delegate ({short}...)")
        }
        // Required by `#[non_exhaustive]` on SignatureRequestor.
        _ => "An unknown caller".to_string(),
    }
}

/// Allocate a fresh prompt request id. Monotonic across the delegate's
/// lifetime so the gateway can track in-flight prompts.
fn next_prompt_request_id() -> u32 {
    static REQUEST_ID_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    REQUEST_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Request permission from the user for a specific-fingerprint operation.
fn request_user_permission(
    ctx: &mut DelegateCtx,
    fingerprint: &str,
    requestor: &SignatureRequestor,
    original_payload: &[u8],
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    use freenet_stdlib::prelude::{ClientResponse, UserInputRequest};

    let request_id = next_prompt_request_id();
    let requestor_desc = requestor_short_label(requestor);

    let prompt = format!(
        "{requestor_desc} is requesting access to your ghostkey identity ({fingerprint}).\n\n\
         Choose 'Allow' to grant access (you can revoke later from the vault), \
         or 'Deny' to block the request."
    );

    logging::info(&format!("Requesting user permission: {prompt}"));

    let pending = PendingPrompt::Fingerprint {
        request_id,
        fingerprint: fingerprint.to_string(),
        requestor: requestor.clone(),
        original_payload: original_payload.to_vec(),
    };
    let pending_bytes =
        to_cbor(&pending).map_err(|e| DelegateError::Other(format!("serialize pending: {e}")))?;
    ctx.write(&pending_bytes);

    // Two-button prompt: persistent grant on Allow, no grant on Deny. The
    // older "Allow Once" / "Always Allow" pair was removed because the
    // "Allow Once" path's revoke-after-replay used `revoke_all`, which
    // would also wipe any pre-existing grants the same requestor held on
    // this fingerprint. Keeping the model simple (every grant persists
    // until explicit revoke) avoids that footgun.
    let user_request = OutboundDelegateMsg::RequestUserInput(UserInputRequest {
        request_id,
        message: {
            let json = serde_json::json!(prompt);
            freenet_stdlib::prelude::NotificationMessage::try_from(&json)
                .expect("string to NotificationMessage")
        },
        responses: vec![
            ClientResponse::new(b"Allow".to_vec()),
            ClientResponse::new(b"Deny".to_vec()),
        ],
    });

    Ok(vec![user_request])
}

/// Handle `RequestAnyAccess`: emit a prompt that lists the user's
/// ghostkeys as buttons so they can pick which one (if any) to share
/// with the requesting app. On approval the delegate grants the
/// third-party scope set for the chosen fingerprint.
fn request_any_access(
    ctx: &mut DelegateCtx,
    requestor: &SignatureRequestor,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    use freenet_stdlib::prelude::{ClientResponse, UserInputRequest};

    // Snapshot the user's ghostkeys so the prompt buttons match the
    // pending state. Loading the index is the same operation handle_list
    // performs; we avoid taking a dependency on handlers here by
    // inlining the secret-store lookup the same way handlers does.
    let fingerprints = handlers::load_index(ctx);

    if fingerprints.is_empty() {
        // No keys to offer -- short-circuit to NoIdentityAvailable
        // rather than render a useless empty prompt. This is a small
        // side-channel (a third-party app can detect "user has no
        // ghostkeys") that we accept in exchange for a usable empty
        // state; a future iteration can replace this with a "Create
        // one" prompt button if the side-channel becomes a concern.
        let response = ghostkey_common::GhostkeyResponse::NoIdentityAvailable;
        let response_bytes = to_cbor(&response)
            .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
        return Ok(vec![OutboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(response_bytes),
        )]);
    }

    // Cap the number of fingerprint buttons so a user with many ghostkeys
    // doesn't get a wall of buttons (and so a future prompt-rendering
    // change isn't burdened with arbitrary list lengths). The cap matches
    // freenet-stdlib's MAX_LABELS for `UserInputRequest::responses` minus
    // one slot reserved for the trailing Deny button.
    const MAX_BUTTON_FINGERPRINTS: usize = 9;
    let fingerprints: Vec<String> = fingerprints
        .into_iter()
        .take(MAX_BUTTON_FINGERPRINTS)
        .collect();

    let request_id = next_prompt_request_id();
    let requestor_desc = requestor_short_label(requestor);

    // Build prompt text. The fingerprint list goes into the message body
    // so the user can see which key each button picks; the buttons
    // themselves carry the fingerprint as part of the label.
    let mut body = format!(
        "{requestor_desc} wants to use one of your ghostkey identities to read your public certificate and sign messages on your behalf.\n\n\
         Pick a key to share, or deny."
    );
    for (i, fp) in fingerprints.iter().enumerate() {
        body.push_str(&format!("\n  {}. {fp}", i + 1));
    }

    logging::info(&format!("Requesting any-access prompt: {body}"));

    let pending = PendingPrompt::AnyAccess {
        request_id,
        requestor: requestor.clone(),
        fingerprints: fingerprints.clone(),
    };
    let pending_bytes =
        to_cbor(&pending).map_err(|e| DelegateError::Other(format!("serialize pending: {e}")))?;
    ctx.write(&pending_bytes);

    // Buttons: one per fingerprint (label is the fingerprint itself), then Deny.
    let mut responses: Vec<ClientResponse<'static>> = fingerprints
        .iter()
        .map(|fp| ClientResponse::new(format!("Share {fp}").into_bytes()))
        .collect();
    responses.push(ClientResponse::new(b"Deny".to_vec()));

    let user_request = OutboundDelegateMsg::RequestUserInput(UserInputRequest {
        request_id,
        message: {
            let json = serde_json::json!(body);
            freenet_stdlib::prelude::NotificationMessage::try_from(&json)
                .expect("string to NotificationMessage")
        },
        responses,
    });

    Ok(vec![user_request])
}

/// Handle the user's response to a permission prompt.
fn handle_user_response(
    ctx: &mut DelegateCtx,
    user_resp: &freenet_stdlib::prelude::UserInputResponse<'_>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // Read pending state from context
    let pending_bytes = ctx.read();
    if pending_bytes.is_empty() {
        return Err(DelegateError::Other(
            "received UserResponse with no pending context".into(),
        ));
    }

    let pending: PendingPrompt = from_cbor(&pending_bytes)
        .map_err(|e| DelegateError::Other(format!("deserialize pending: {e}")))?;

    ctx.clear();

    match pending {
        PendingPrompt::Fingerprint {
            fingerprint,
            requestor,
            original_payload,
            ..
        } => handle_fingerprint_response(ctx, user_resp, fingerprint, requestor, original_payload),
        PendingPrompt::AnyAccess {
            requestor,
            fingerprints,
            ..
        } => handle_any_access_response(ctx, user_resp, requestor, fingerprints),
    }
}

/// Single-fingerprint approval flow: the user clicked Allow or Deny on a
/// permission prompt for a specific key. On approval we grant the
/// third-party scope set, then replay the original request. The grant
/// persists until explicit revoke (the prior "Allow Once" path was
/// removed because its revoke-after-replay used `revoke_all`, which
/// would also drop unrelated pre-existing grants the same requestor
/// held on this fingerprint).
fn handle_fingerprint_response(
    ctx: &mut DelegateCtx,
    user_resp: &freenet_stdlib::prelude::UserInputResponse<'_>,
    fingerprint: String,
    requestor: SignatureRequestor,
    original_payload: Vec<u8>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let response_bytes = user_resp.response.bytes();
    let approved = response_bytes == b"Allow";

    if !approved {
        logging::info(&format!("User denied access to ghostkey {fingerprint}"));
        let response = ghostkey_common::GhostkeyResponse::PermissionDenied {
            fingerprint,
            requestor,
        };
        let response_bytes = to_cbor(&response)
            .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
        return Ok(vec![OutboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(response_bytes),
        )]);
    }

    logging::info(&format!("User approved access to ghostkey {fingerprint}"));

    // Grant the third-party scope set so the requesting app can read the
    // public certificate and sign messages with this key. Higher-privilege
    // operations (Export/Delete/Admin) deliberately stay vault-only and
    // never reach this code path -- `handle_request` hard-denies them
    // before a prompt fires.
    permissions::grant_third_party(ctx, &fingerprint, &requestor);

    let request: GhostkeyRequest = from_cbor(&original_payload)
        .map_err(|e| DelegateError::Other(format!("deserialize original request: {e}")))?;

    let response = handlers::handle(ctx, request, &requestor);

    let response_bytes =
        to_cbor(&response).map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}

/// `RequestAnyAccess` approval flow: the user picked one of the
/// fingerprint buttons (or the trailing Deny button). On a fingerprint
/// pick, grant the third-party scope set and reply with a single-element
/// `GhostKeyList` so the requesting app sees only the key the user chose
/// to share.
fn handle_any_access_response(
    ctx: &mut DelegateCtx,
    user_resp: &freenet_stdlib::prelude::UserInputResponse<'_>,
    requestor: SignatureRequestor,
    fingerprints: Vec<String>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let response_bytes = user_resp.response.bytes();

    // The Deny button is the last in the response list; matching on the
    // exact label is more robust than indexing because the label set is
    // small and stable.
    if response_bytes == b"Deny" {
        logging::info("User denied any-access request");
        let response = ghostkey_common::GhostkeyResponse::AccessDenied { requestor };
        let response_bytes = to_cbor(&response)
            .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
        return Ok(vec![OutboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(response_bytes),
        )]);
    }

    // Otherwise the response is "Share <fingerprint>". Map it back to one
    // of the fingerprints we offered. We don't trust the suffix from the
    // user response alone -- the prompt UI is server-rendered and the
    // browser shouldn't be able to inject arbitrary text, but checking
    // membership in our pinned fingerprint list is cheap defense in depth.
    let chosen: Option<String> = fingerprints
        .into_iter()
        .find(|fp| response_bytes == format!("Share {fp}").as_bytes());

    let Some(fp) = chosen else {
        logging::info("Any-access response did not match any known fingerprint button");
        let response = ghostkey_common::GhostkeyResponse::AccessDenied { requestor };
        let response_bytes = to_cbor(&response)
            .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
        return Ok(vec![OutboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(response_bytes),
        )]);
    };

    logging::info(&format!(
        "User approved any-access: granting third-party scopes on {fp}"
    ));
    permissions::grant_third_party(ctx, &fp, &requestor);

    // Synthesise a `GhostKeyList` containing exactly the key the user
    // chose to share. Routing through `ListGhostKeys` is wrong here: if
    // the same requestor already had a grant on other keys (from a prior
    // share), `ListGhostKeys` would return ALL of them, leaking more
    // identities than the user just authorised in this prompt.
    let response = handlers::lookup_single_key(ctx, &fp);
    let response_bytes =
        to_cbor(&response).map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::ContractInstanceId;

    fn webapp(seed: u8) -> SignatureRequestor {
        let bytes = [seed; 32];
        let id = ContractInstanceId::from_bytes(bs58::encode(&bytes).into_string()).unwrap();
        SignatureRequestor::WebApp(id)
    }

    /// Wire-pin for `PendingPrompt`. The enum is persisted via
    /// `ctx.write` between two delegate invocations (prompt emit, then
    /// user response). A rename or reorder of variants here would silently
    /// drop every in-flight prompt the next time a user clicks Allow,
    /// because the second invocation's `from_cbor` would fail. This test
    /// fails on any such change, forcing an explicit migration plan.
    #[test]
    fn pending_prompt_wire_format_is_stable() {
        let fp = PendingPrompt::Fingerprint {
            request_id: 7,
            fingerprint: "ciQaxxSwKF8".into(),
            requestor: webapp(0xab),
            original_payload: vec![1, 2, 3],
        };
        let any = PendingPrompt::AnyAccess {
            request_id: 8,
            requestor: webapp(0xcd),
            fingerprints: vec!["fp1".into(), "fp2".into()],
        };
        for variant in [&fp, &any] {
            let bytes = to_cbor(variant).unwrap();
            // Round-trip exactly.
            let _decoded: PendingPrompt = from_cbor(&bytes).unwrap();
        }

        // Pin the JSON variant names so a rename is loud.
        let fp_json = serde_json::to_string(&fp).unwrap();
        assert!(
            fp_json.starts_with(r#"{"Fingerprint":"#),
            "Fingerprint variant name shifted: {fp_json}"
        );
        let any_json = serde_json::to_string(&any).unwrap();
        assert!(
            any_json.starts_with(r#"{"AnyAccess":"#),
            "AnyAccess variant name shifted: {any_json}"
        );
    }
}
