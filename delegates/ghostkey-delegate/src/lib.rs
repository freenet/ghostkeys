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
                // Emit a user prompt and store the pending request so we
                // can replay it after the user approves.
                return request_user_permission(ctx, &fp, requestor, payload);
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
         Choose 'Allow' for one-time access, 'Always Allow' to remember this choice, \
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

    let user_request = OutboundDelegateMsg::RequestUserInput(UserInputRequest {
        request_id,
        message: {
            let json = serde_json::json!(prompt);
            freenet_stdlib::prelude::NotificationMessage::try_from(&json)
                .expect("string to NotificationMessage")
        },
        responses: vec![
            ClientResponse::new(b"Allow Once".to_vec()),
            ClientResponse::new(b"Always Allow".to_vec()),
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

    let request_id = next_prompt_request_id();
    let requestor_desc = requestor_short_label(requestor);

    // Build prompt text. The fingerprint list is short (cap on
    // MAX_PENDING_PROMPTS keeps it bounded in practice) and goes into
    // the message body so the user can see which key each button picks.
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

/// Single-fingerprint approval flow: the user clicked Allow Once / Always
/// Allow / Deny on a permission prompt for a specific key. On approval we
/// grant the third-party scope set (or the full scope set if the caller
/// is the same identity that already imported the key, but that branch is
/// unreachable in practice -- the importer auto-grants on import), replay
/// the original request, and revert the grant if the user chose
/// "Allow Once".
fn handle_fingerprint_response(
    ctx: &mut DelegateCtx,
    user_resp: &freenet_stdlib::prelude::UserInputResponse<'_>,
    fingerprint: String,
    requestor: SignatureRequestor,
    original_payload: Vec<u8>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let response_bytes = user_resp.response.bytes();
    let approved = response_bytes == b"Allow Once" || response_bytes == b"Always Allow";

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

    let permanent = response_bytes == b"Always Allow";
    logging::info(&format!(
        "User approved access to ghostkey {fingerprint} (permanent={permanent})"
    ));

    // Grant the third-party scope set so the requesting app can read the
    // public certificate and sign messages with this key. Higher-privilege
    // operations (Export/Delete/Admin) deliberately stay vault-only.
    permissions::grant_third_party(ctx, &fingerprint, &requestor);

    let request: GhostkeyRequest = from_cbor(&original_payload)
        .map_err(|e| DelegateError::Other(format!("deserialize original request: {e}")))?;

    let response = handlers::handle(ctx, request, &requestor);

    if !permanent {
        // "Allow Once" -- remove the just-added grant after replaying the
        // request. Subsequent calls from the same requestor will re-prompt.
        permissions::revoke_all(ctx, &fingerprint, &requestor);
    }

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

    // Synthesise a one-element GhostKeyList for the granted key. This is
    // exactly what `ListGhostKeys` would return now that the grant
    // exists; we route through `handlers::handle` to keep the response
    // shape canonical.
    let response = handlers::handle(ctx, GhostkeyRequest::ListGhostKeys, &requestor);

    let response_bytes =
        to_cbor(&response).map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}
