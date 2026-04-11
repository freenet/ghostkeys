#![allow(unexpected_cfgs)]

mod handlers;
mod logging;
mod permissions;

use freenet_stdlib::prelude::{
    delegate, ApplicationMessage, DelegateContext, DelegateCtx, DelegateError, DelegateInterface,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, Parameters,
};

use ghostkey_common::{from_cbor, to_cbor, GhostkeyRequest, SignatureRequestor};

/// Pending permission request stored in DelegateContext while awaiting user input.
#[derive(serde::Serialize, serde::Deserialize)]
struct PendingPermission {
    request_id: u32,
    fingerprint: String,
    requestor: SignatureRequestor,
    /// The original request payload to replay after approval.
    original_payload: Vec<u8>,
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
                    None => {
                        return Err(DelegateError::Other(
                            "missing message origin for application message".into(),
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

    // Permission-sensitive operations check access first
    if requires_permission(&request) {
        if let Some(fp) = get_fingerprint(&request) {
            if !permissions::is_allowed(ctx, &fp, requestor) {
                // Emit a user prompt and store the pending request in context
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

/// Check if a request requires permission.
fn requires_permission(request: &GhostkeyRequest) -> bool {
    matches!(
        request,
        GhostkeyRequest::GetGhostKey { .. }
            | GhostkeyRequest::GetCertificate { .. }
            | GhostkeyRequest::SignMessage { .. }
            | GhostkeyRequest::DeleteGhostKey { .. }
    )
}

/// Extract the fingerprint from a request, if applicable.
fn get_fingerprint(request: &GhostkeyRequest) -> Option<String> {
    match request {
        GhostkeyRequest::GetGhostKey { fingerprint }
        | GhostkeyRequest::GetCertificate { fingerprint }
        | GhostkeyRequest::SignMessage { fingerprint, .. }
        | GhostkeyRequest::DeleteGhostKey { fingerprint }
        | GhostkeyRequest::SetLabel { fingerprint, .. } => Some(fingerprint.clone()),
        _ => None,
    }
}

/// Request permission from the user via the browser prompt system.
fn request_user_permission(
    ctx: &mut DelegateCtx,
    fingerprint: &str,
    requestor: &SignatureRequestor,
    original_payload: &[u8],
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    use freenet_stdlib::prelude::{ClientResponse, UserInputRequest};
    use std::borrow::Cow;

    static REQUEST_ID_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let request_id = REQUEST_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let requestor_desc = match requestor {
        SignatureRequestor::WebApp(id) => format!("Web app {}", id),
        SignatureRequestor::Delegate(key) => format!("Delegate {}", key.encode()),
    };

    let prompt = format!(
        "{} wants to access ghostkey {}. Allow?",
        requestor_desc, fingerprint
    );

    logging::info(&format!("Requesting user permission: {prompt}"));

    // Store pending state in context so we can replay after approval
    let pending = PendingPermission {
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
            ClientResponse::new(b"allow".to_vec()),
            ClientResponse::new(b"always_allow".to_vec()),
            ClientResponse::new(b"deny".to_vec()),
        ],
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

    let pending: PendingPermission = from_cbor(&pending_bytes)
        .map_err(|e| DelegateError::Other(format!("deserialize pending: {e}")))?;

    ctx.clear();

    let response_bytes = user_resp.response.bytes();

    if response_bytes == b"allow" || response_bytes == b"always_allow" {
        logging::info(&format!(
            "User approved access to ghostkey {}",
            pending.fingerprint
        ));

        let permanent = response_bytes == b"always_allow";

        // Grant permission (permanent or temporary for replay)
        permissions::grant(ctx, &pending.fingerprint, &pending.requestor);

        if permanent {
            logging::info("Permission saved permanently");
        }

        // Replay the original request
        let request: GhostkeyRequest = from_cbor(&pending.original_payload)
            .map_err(|e| DelegateError::Other(format!("deserialize original request: {e}")))?;

        let response = handlers::handle(ctx, request, &pending.requestor);

        // Revoke if it was "allow once"
        if !permanent {
            permissions::revoke(ctx, &pending.fingerprint, &pending.requestor);
        }

        let response_bytes = to_cbor(&response)
            .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;

        Ok(vec![OutboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(response_bytes),
        )])
    } else {
        logging::info(&format!(
            "User denied access to ghostkey {}",
            pending.fingerprint
        ));

        let response = ghostkey_common::GhostkeyResponse::PermissionDenied {
            fingerprint: pending.fingerprint,
            requestor: pending.requestor,
        };
        let response_bytes = to_cbor(&response)
            .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;

        Ok(vec![OutboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(response_bytes),
        )])
    }
}
