#![allow(unexpected_cfgs)]

mod env;
mod handlers;
mod logging;
mod permissions;

use env::DelegateEnv;

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
    /// A request that needs *some* ghostkey but names none
    /// (`SignWithDefault`, `GetDefaultKey`) from a caller with no grant yet.
    ///
    /// Same picker as `AnyAccess`, but the original request is replayed once
    /// the user chooses, so the caller gets the signature it asked for rather
    /// than a key list it then has to act on.
    AnyAccessThenReplay {
        request_id: u32,
        requestor: SignatureRequestor,
        fingerprints: Vec<String>,
        original_payload: Vec<u8>,
    },
    /// Confirmation for an operation that hands out a raw private signing key.
    ///
    /// Unlike every other variant this grants NOTHING on approval. The caller
    /// already holds `Export`; the prompt exists precisely because holding a
    /// stored grant is not sufficient authority to extract a private key. The
    /// approval covers the one replayed request and is not remembered.
    ExportConfirm {
        request_id: u32,
        requestor: SignatureRequestor,
        /// The key being exported, for a single-key export. `None` for
        /// `ExportAllGhostKeys`, which names no fingerprint.
        fingerprint: Option<String>,
        original_payload: Vec<u8>,
    },
}

impl PendingPrompt {
    /// The prompt id this pending state was shown to the user under. Used to
    /// reject a response belonging to a different prompt -- see
    /// `handle_user_response`.
    fn request_id(&self) -> u32 {
        match self {
            PendingPrompt::Fingerprint { request_id, .. }
            | PendingPrompt::AnyAccess { request_id, .. }
            | PendingPrompt::AnyAccessThenReplay { request_id, .. }
            | PendingPrompt::ExportConfirm { request_id, .. } => *request_id,
        }
    }
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
    ctx: &mut dyn DelegateEnv,
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

    // `SignWithDefault` needs SOME key but names none, so the
    // fingerprint-scoped check below cannot see it. Without this, a caller
    // holding no grant fell through to `resolve_default`, which filters by
    // `Sign` scope, found nothing, and answered `NoIdentityAvailable` --
    // telling an app that the user owns no ghostkey when the truth was that
    // the app had never asked for permission. An app following that answer
    // sends someone who already paid for a ghostkey off to buy a second one.
    //
    // The honest split: if the vault is genuinely empty, `NoIdentityAvailable`
    // is correct and the handler below returns it. If it holds keys, ask the
    // user and replay.
    if acts_on_a_key_it_does_not_name(&request) {
        // Ranked and signable-only: the picker shows at most
        // MAX_BUTTON_FINGERPRINTS buttons, index order is import order, and a
        // certificate whose signing key is gone would be offered, approved,
        // and then fail to sign.
        let fingerprints = handlers::signable_fingerprints_by_tier_desc(ctx);
        match default_key_route(
            handlers::resolve_default(ctx, requestor).is_some(),
            fingerprints.is_empty(),
        ) {
            DefaultKeyRoute::Prompt => {
                return request_any_access_then_replay(ctx, requestor, payload, fingerprints)
            }
            // Both fall through to the handler: it answers with the resolved
            // key, or with `NoIdentityAvailable` when the vault is genuinely
            // empty.
            DefaultKeyRoute::Proceed | DefaultKeyRoute::NoIdentity => {}
        }
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

    // Handing out a raw private key is never authorised by a stored grant
    // alone, no matter who holds it. A grant is a decision the user made once,
    // possibly months ago, in a different context; an exported signing key is
    // irrevocable and works forever without their node. So the export path
    // asks again, every time, and the answer is not remembered.
    //
    // This runs AFTER the scope check above on purpose: a caller with no
    // `Export` grant is still hard-denied without a prompt, so an app cannot
    // put a scary dialog in front of the user for an operation that would be
    // refused anyway.
    if let Some(subject) = export_confirmation_subject(ctx, &request, requestor) {
        return request_export_confirmation(ctx, requestor, payload, subject);
    }

    let response = handlers::handle(ctx, request, requestor);

    let response_bytes =
        to_cbor(&response).map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;

    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(response_bytes),
    )])
}

/// Park a pending prompt in the delegate's context slot, failing the request
/// if it cannot be stored.
///
/// The write can fail (oversize context, or a runtime that rejects it), and
/// ignoring the result leaves the PREVIOUS pending prompt in the slot while
/// the new dialog is on screen -- so the user's click would answer a question
/// they are no longer being asked. Refusing to raise the prompt is better.
fn park_pending(ctx: &mut dyn DelegateEnv, bytes: &[u8]) -> Result<(), DelegateError> {
    if ctx.context_write(bytes) {
        Ok(())
    } else {
        ctx.context_clear();
        Err(DelegateError::Other(
            "could not store the pending user prompt".into(),
        ))
    }
}

/// Requests that hand the caller raw private signing keys.
///
/// `MarkBackedUp` is deliberately absent even though it is gated on the same
/// `Export` scope: it writes a flag and discloses nothing, and the vault sends
/// it immediately after a successful export, so prompting for it would mean
/// two dialogs for one user action.
fn discloses_private_key(request: &GhostkeyRequest) -> bool {
    matches!(
        request,
        GhostkeyRequest::ExportGhostKey { .. } | GhostkeyRequest::ExportAllGhostKeys
    )
}

/// What an export-confirmation prompt is about.
#[derive(Debug, PartialEq, Eq)]
enum ExportSubject {
    /// One named key.
    Single(String),
    /// Every key the caller could extract, and how many that is.
    All(usize),
}

/// Decide whether this request needs a fresh confirmation, and what the prompt
/// should say it is about. `None` means "carry on to the handler".
///
/// For `ExportGhostKey` the scope check in `handle_request` has already run, so
/// reaching here means the caller holds `Export` on that key. `ExportAllGhostKeys`
/// names no fingerprint and so is never scope-checked there; it is filtered
/// per-key inside the handler instead. Returning `None` when the caller could
/// export nothing preserves that: an app with no grants gets the same empty
/// list it always got, rather than the power to raise a dialog by asking.
fn export_confirmation_subject(
    ctx: &dyn DelegateEnv,
    request: &GhostkeyRequest,
    requestor: &SignatureRequestor,
) -> Option<ExportSubject> {
    match request {
        // Not prompting for a key the vault does not hold: the handler answers
        // `KeyNotFound`, and raising the full private-key warning first would
        // ask the user to authorise disclosing something that does not exist.
        GhostkeyRequest::ExportGhostKey { fingerprint } => {
            handlers::has_certificate(ctx, fingerprint)
                .then(|| ExportSubject::Single(fingerprint.clone()))
        }
        GhostkeyRequest::ExportAllGhostKeys => {
            let count = handlers::exportable_count(ctx, requestor);
            (count > 0).then_some(ExportSubject::All(count))
        }
        _ => None,
    }
}

/// Ask the user to confirm a private-key export.
///
/// Nothing is granted by approving: the caller already holds `Export`, and the
/// point of this prompt is that holding it is not enough. The approval
/// authorises exactly the request that is replayed, once.
fn request_export_confirmation(
    ctx: &mut dyn DelegateEnv,
    requestor: &SignatureRequestor,
    original_payload: &[u8],
    subject: ExportSubject,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    use freenet_stdlib::prelude::{ClientResponse, UserInputRequest};

    let request_id = next_prompt_request_id(ctx);
    let requestor_desc = requestor_short_label(requestor);

    let (what, fingerprint) = match subject {
        ExportSubject::Single(fp) => {
            let name = handlers::get_label(ctx, &fp).unwrap_or_else(|| fp.clone());
            (format!("your ghostkey \"{name}\""), Some(fp))
        }
        ExportSubject::All(1) => ("your ghostkey".to_string(), None),
        ExportSubject::All(n) => (format!("all {n} of your ghostkeys"), None),
    };

    let prompt = format!(
        "{requestor_desc} wants to take a copy of {what}, including the PRIVATE key.\n\n\
         Anyone who gets that copy can sign as you forever, from anywhere, and it cannot \
         be revoked. Only allow this if you just asked for a backup.\n\n\
         Allow, or deny?"
    );

    logging::info(&format!("Requesting export confirmation: {prompt}"));

    let pending = PendingPrompt::ExportConfirm {
        request_id,
        requestor: requestor.clone(),
        fingerprint,
        original_payload: original_payload.to_vec(),
    };
    let pending_bytes =
        to_cbor(&pending).map_err(|e| DelegateError::Other(format!("serialize pending: {e}")))?;
    park_pending(ctx, &pending_bytes)?;

    Ok(vec![OutboundDelegateMsg::RequestUserInput(
        UserInputRequest {
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
        },
    )])
}

/// Handle the answer to an export confirmation.
///
/// Approving grants nothing and is not remembered: the next export asks again.
fn handle_export_confirm_response(
    ctx: &mut dyn DelegateEnv,
    user_resp: &freenet_stdlib::prelude::UserInputResponse<'_>,
    requestor: SignatureRequestor,
    fingerprint: Option<String>,
    original_payload: Vec<u8>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let denial = |requestor: SignatureRequestor| match &fingerprint {
        Some(fp) => ghostkey_common::GhostkeyResponse::PermissionDenied {
            fingerprint: fp.clone(),
            requestor,
        },
        None => ghostkey_common::GhostkeyResponse::AccessDenied { requestor },
    };

    if user_resp.response.bytes() != b"Allow" {
        logging::info("User denied a private-key export");
        return respond(denial(requestor));
    }

    let request: GhostkeyRequest = from_cbor(&original_payload)
        .map_err(|e| DelegateError::Other(format!("deserialize original request: {e}")))?;

    // The payload was written by `request_export_confirmation` and read back
    // from the delegate's own context, so it should always be an export. Check
    // anyway: an approval collected for "hand me your private key" must not be
    // spendable on any other operation if that context slot is ever reachable
    // from somewhere else.
    if !discloses_private_key(&request) {
        logging::info("Export confirmation replayed a non-export request; refusing");
        return respond(denial(requestor));
    }

    logging::info("User approved a private-key export");
    let response = handlers::handle(ctx, request, &requestor);
    respond(response)
}

/// Wrap a response as the single outbound application message.
fn respond(
    response: ghostkey_common::GhostkeyResponse,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let bytes =
        to_cbor(&response).map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
    Ok(vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(bytes),
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
        // `MarkBackedUp` writes a flag that suppresses a backup warning, so
        // it is gated on the vault-only `Export` scope: an app that cannot
        // export the key has no backup of it and no business silencing the
        // warning. `handle_mark_backed_up` enforces this too -- declaring it
        // here keeps the table complete rather than relying on the catch-all.
        GhostkeyRequest::ExportGhostKey { .. } | GhostkeyRequest::MarkBackedUp { .. } => {
            Some(GhostkeyScope::Export)
        }
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
        | GhostkeyRequest::MarkBackedUp { fingerprint }
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

/// Allocate a prompt request id that is unique across invocations.
///
/// This lives in the secret store rather than in a `static` on purpose. The
/// runtime builds a FRESH wasm instance for every inbound application message
/// (`RunningInstance::new` per `prepare_delegate_call` in freenet-core), so
/// module statics are re-initialised each call and an in-memory counter hands
/// out `1` for the first prompt of every invocation. Colliding ids would make
/// the check in `handle_user_response` -- that an answer belongs to the
/// question it was asked about -- silently vacuous, which is worse than not
/// having it: the delegate would look bound and not be.
///
/// Wrapping is handled rather than ignored, skipping `0` so a wrapped counter
/// cannot collide with an uninitialised read.
fn next_prompt_request_id(ctx: &mut dyn DelegateEnv) -> u32 {
    let current = ctx
        .get_secret(PROMPT_SEQ_KEY)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);
    let next = match current.wrapping_add(1) {
        0 => 1,
        n => n,
    };
    ctx.set_secret(PROMPT_SEQ_KEY, &next.to_le_bytes());
    next
}

/// Secret-store slot holding the prompt-id counter.
const PROMPT_SEQ_KEY: &[u8] = b"gk:prompt-seq";

/// One offerable key in a picker prompt: which fingerprint it is, what to
/// show for it (the user's label if set, else the fingerprint), and the
/// exact button-response bytes that select it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyChoice {
    fingerprint: String,
    display: String,
    response: Vec<u8>,
}

/// Build `KeyChoice`s from fingerprints paired with their already-resolved
/// display names (the user's label if set, else the fingerprint itself).
/// Pure and `DelegateCtx`-free so the disambiguation logic is unit-testable
/// without a live delegate context; `key_choices` below is the thin
/// ctx-aware wrapper every real caller uses.
///
/// A single offered key collapses to a plain "Allow" button: there is
/// nothing to disambiguate, so naming the key would just be noise. Two or
/// more keys get a named button each, disambiguated in stages so a
/// response can never match more than one candidate -- see
/// `duplicate_display_names_are_disambiguated_by_fingerprint` and
/// `three_way_label_collision_is_still_disambiguated` for the cases this
/// guards, including one a single "append fingerprint to the duplicates
/// only" pass gets wrong: a key labelled literally `"Work (fpA)"` colliding
/// with another key named "Work" whose disambiguated form is `"Work
/// (fpA)"`.
fn key_choices_from_names(fingerprints: &[String], names: Vec<String>) -> Vec<KeyChoice> {
    debug_assert_eq!(fingerprints.len(), names.len());

    if let ([fp], [name]) = (fingerprints, names.as_slice()) {
        return vec![KeyChoice {
            fingerprint: fp.clone(),
            display: name.clone(),
            response: b"Allow".to_vec(),
        }];
    }

    let mut displays = names;

    // Stage 1: if ANY name collides with another, append every key's own
    // fingerprint to its name -- not just the colliding ones. Appending
    // only to the duplicates would leave an untouched key's plain label
    // free to coincidentally match a just-disambiguated neighbour's new
    // name; applying it to the whole group avoids that by construction.
    if has_duplicates(&displays) {
        for (display, fp) in displays.iter_mut().zip(fingerprints) {
            *display = format!("{display} ({fp})");
        }
    }

    // Stage 2 (defense in depth, expected to be unreachable in practice):
    // a hand-set label that happens to reproduce another key's stage-1
    // output verbatim. Break any surviving tie with each entry's position,
    // which is unique by construction, guaranteeing every display -- and
    // therefore every button's response bytes -- is unique regardless of
    // label content.
    if has_duplicates(&displays) {
        for (i, display) in displays.iter_mut().enumerate() {
            *display = format!("{display} #{}", i + 1);
        }
    }

    fingerprints
        .iter()
        .cloned()
        .zip(displays)
        .map(|(fingerprint, display)| {
            let response = format!("Allow \"{display}\"").into_bytes();
            KeyChoice {
                fingerprint,
                display,
                response,
            }
        })
        .collect()
}

fn has_duplicates(items: &[String]) -> bool {
    let unique: std::collections::HashSet<&String> = items.iter().collect();
    unique.len() != items.len()
}

/// Build the offerable choices for a key-picker prompt, resolving each
/// fingerprint's display name from the user's saved label. Used both to
/// render the prompt (body list + buttons) and, later, to match the user's
/// response back to a fingerprint -- the two must derive from the same
/// function so they can never drift apart.
fn key_choices(ctx: &dyn DelegateEnv, fingerprints: &[String]) -> Vec<KeyChoice> {
    let names = fingerprints
        .iter()
        .map(|fp| handlers::get_label(ctx, fp).unwrap_or_else(|| fp.clone()))
        .collect();
    key_choices_from_names(fingerprints, names)
}

/// Request permission from the user for a specific-fingerprint operation.
fn request_user_permission(
    ctx: &mut dyn DelegateEnv,
    fingerprint: &str,
    requestor: &SignatureRequestor,
    original_payload: &[u8],
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    use freenet_stdlib::prelude::{ClientResponse, UserInputRequest};

    let request_id = next_prompt_request_id(ctx);
    let requestor_desc = requestor_short_label(requestor);

    let key_name = handlers::get_label(ctx, fingerprint).unwrap_or_else(|| fingerprint.to_string());
    let prompt = format!(
        "{requestor_desc} wants to use your ghostkey \"{key_name}\" as proof you're a real \
         person, not a bot, while staying anonymous. It can only ask for a signature — never \
         your private key.\n\n\
         Allow, or deny?"
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
    park_pending(ctx, &pending_bytes)?;

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
    ctx: &mut dyn DelegateEnv,
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

    let request_id = next_prompt_request_id(ctx);
    let requestor_desc = requestor_short_label(requestor);
    let choices = key_choices(ctx, &fingerprints);

    // Build prompt text. A single offered key needs no picker -- just
    // Allow/Deny, matching the specific-fingerprint prompt above. Two or
    // more keys get a numbered list (using each key's label, so the user
    // sees a name they picked rather than an opaque fingerprint) plus a
    // named button per key.
    let mut body = format!(
        "{requestor_desc} wants to use one of your ghostkeys as proof you're a real person, \
         not a bot, while staying anonymous. It can only ask for a signature — never your \
         private key.\n\n"
    );
    if choices.len() == 1 {
        body.push_str("Allow, or deny?");
    } else {
        body.push_str("Pick which key to allow, or deny.");
        for (i, choice) in choices.iter().enumerate() {
            body.push_str(&format!("\n  {}. {}", i + 1, choice.display));
        }
    }

    logging::info(&format!("Requesting any-access prompt: {body}"));

    let pending = PendingPrompt::AnyAccess {
        request_id,
        requestor: requestor.clone(),
        fingerprints: fingerprints.clone(),
    };
    let pending_bytes =
        to_cbor(&pending).map_err(|e| DelegateError::Other(format!("serialize pending: {e}")))?;
    park_pending(ctx, &pending_bytes)?;

    let mut responses: Vec<ClientResponse<'static>> = choices
        .into_iter()
        .map(|c| ClientResponse::new(c.response))
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

/// Emit the key picker for a request that needs a key but names none, keeping
/// the original request so it can be replayed on approval.
fn request_any_access_then_replay(
    ctx: &mut dyn DelegateEnv,
    requestor: &SignatureRequestor,
    original_payload: &[u8],
    fingerprints: Vec<String>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    use freenet_stdlib::prelude::{ClientResponse, UserInputRequest};

    const MAX_BUTTON_FINGERPRINTS: usize = 9;
    let fingerprints: Vec<String> = fingerprints
        .into_iter()
        .take(MAX_BUTTON_FINGERPRINTS)
        .collect();

    let request_id = next_prompt_request_id(ctx);
    let requestor_desc = requestor_short_label(requestor);
    let choices = key_choices(ctx, &fingerprints);

    let mut body = format!(
        "{requestor_desc} wants to sign something here using one of your ghostkeys — as \
         proof you're a real person, not a bot, while staying anonymous. It can only ask \
         for a signature — never your private key.\n\n"
    );
    if choices.len() == 1 {
        body.push_str("Allow, or deny?");
    } else {
        body.push_str("Pick which key to allow, or deny.");
        for (i, choice) in choices.iter().enumerate() {
            body.push_str(&format!("\n  {}. {}", i + 1, choice.display));
        }
    }

    logging::info(&format!("Requesting sign-with-default prompt: {body}"));

    let pending = PendingPrompt::AnyAccessThenReplay {
        request_id,
        requestor: requestor.clone(),
        fingerprints: fingerprints.clone(),
        original_payload: original_payload.to_vec(),
    };
    let pending_bytes =
        to_cbor(&pending).map_err(|e| DelegateError::Other(format!("serialize pending: {e}")))?;
    park_pending(ctx, &pending_bytes)?;

    let mut responses: Vec<ClientResponse<'static>> = choices
        .into_iter()
        .map(|c| ClientResponse::new(c.response))
        .collect();
    responses.push(ClientResponse::new(b"Deny".to_vec()));

    Ok(vec![OutboundDelegateMsg::RequestUserInput(
        UserInputRequest {
            request_id,
            message: {
                let json = serde_json::json!(body);
                freenet_stdlib::prelude::NotificationMessage::try_from(&json)
                    .expect("string to NotificationMessage")
            },
            responses,
        },
    )])
}

/// Handle the user's response to a permission prompt.
fn handle_user_response(
    ctx: &mut dyn DelegateEnv,
    user_resp: &freenet_stdlib::prelude::UserInputResponse<'_>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    // Read pending state from context
    let pending_bytes = ctx.context_read();
    if pending_bytes.is_empty() {
        return Err(DelegateError::Other(
            "received UserResponse with no pending context".into(),
        ));
    }

    let pending: PendingPrompt = from_cbor(&pending_bytes)
        .map_err(|e| DelegateError::Other(format!("deserialize pending: {e}")))?;

    ctx.context_clear();

    // An answer only counts for the question it was asked about.
    //
    // There is exactly one pending-prompt slot per delegate, so a second
    // prompt overwrites the first while the first is still on screen. Without
    // this the delegate runs whatever is parked at click time, so a click on
    // one dialog executes another dialog's pending action -- and the button
    // bytes overlap (a single-key access prompt and an export confirmation
    // both use `Allow`), so nothing else tells them apart. Every variant
    // already carries the id it was shown under; this is what makes carrying
    // it mean something.
    if user_resp.request_id != pending.request_id() {
        logging::info(
            "Discarding a user response whose request id does not match the pending prompt",
        );
        return Err(DelegateError::Other(
            "user response does not match the pending prompt".into(),
        ));
    }

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
        PendingPrompt::AnyAccessThenReplay {
            requestor,
            fingerprints,
            original_payload,
            ..
        } => handle_any_access_then_replay_response(
            ctx,
            user_resp,
            requestor,
            fingerprints,
            original_payload,
        ),
        PendingPrompt::ExportConfirm {
            requestor,
            fingerprint,
            original_payload,
            ..
        } => {
            handle_export_confirm_response(ctx, user_resp, requestor, fingerprint, original_payload)
        }
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
    ctx: &mut dyn DelegateEnv,
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
    ctx: &mut dyn DelegateEnv,
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

    // Otherwise the response is one of the "Allow ..." choices we built the
    // prompt with. Recompute the same choices (rather than trusting a
    // suffix parsed from the response) and match by exact bytes -- the
    // prompt UI is server-rendered and the browser shouldn't be able to
    // inject arbitrary text, but checking membership in our pinned
    // fingerprint list is cheap defense in depth.
    let choices = key_choices(ctx, &fingerprints);
    let chosen: Option<String> = match match_offered_fingerprint(response_bytes, &choices) {
        AnyAccessChoice::Chose(fp) => Some(fp),
        _ => None,
    };

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

/// Which requests take an action needing *some* ghostkey while naming no
/// fingerprint, so the fingerprint-scoped permission check further down cannot
/// see them.
///
/// `GetDefaultKey` is deliberately NOT here even though it also names no
/// fingerprint. It is a question, not an action, and prompting on a question
/// hands every app a way to raise a modal dialog on page load without the user
/// doing anything. Its unhelpful `DefaultKeyResult { None }` for an ungranted
/// caller is the thing `HasIdentity` exists to answer without a prompt.
fn acts_on_a_key_it_does_not_name(request: &GhostkeyRequest) -> bool {
    matches!(request, GhostkeyRequest::SignWithDefault { .. })
}

/// What to do with a request that needs a key but names none.
#[derive(Debug, PartialEq, Eq)]
enum DefaultKeyRoute {
    /// The caller already has a usable key; the handler answers directly.
    Proceed,
    /// The vault holds keys the caller has no grant on. Ask the user.
    Prompt,
    /// The vault is genuinely empty; `NoIdentityAvailable` is the truth.
    NoIdentity,
}

/// The three-way split that keeps `NoIdentityAvailable` honest.
///
/// Before this existed, a caller with no grant fell through to
/// `resolve_default`, which filters by `Sign` scope, found nothing, and got
/// `NoIdentityAvailable` -- telling an app the user owns no ghostkey when the
/// truth was that the app had never asked. An app following that answer sends
/// someone who already paid off to buy a second key.
fn default_key_route(has_resolvable_default: bool, index_empty: bool) -> DefaultKeyRoute {
    match (has_resolvable_default, index_empty) {
        (true, _) => DefaultKeyRoute::Proceed,
        (false, false) => DefaultKeyRoute::Prompt,
        (false, true) => DefaultKeyRoute::NoIdentity,
    }
}

/// The user's answer to a key-picker prompt.
#[derive(Debug, PartialEq, Eq)]
enum AnyAccessChoice {
    Chose(String),
    Denied,
    /// The response matched neither `Deny` nor any offered fingerprint.
    /// Treated as a denial: granting on an unrecognised button would mean
    /// acting on a choice the user was never shown.
    Unrecognized,
}

/// Match a prompt response back to a fingerprint the delegate actually
/// offered, rather than parsing the response's suffix. `offered` is the same
/// `key_choices` output the prompt was built from (recomputed from the
/// fingerprint list stored with the pending prompt), so a fingerprint that
/// never made it onto a button can never be selected.
fn match_offered_fingerprint(response: &[u8], offered: &[KeyChoice]) -> AnyAccessChoice {
    if response == b"Deny" {
        return AnyAccessChoice::Denied;
    }
    match offered.iter().find(|c| response == c.response.as_slice()) {
        Some(c) => AnyAccessChoice::Chose(c.fingerprint.clone()),
        None => AnyAccessChoice::Unrecognized,
    }
}

/// Approval flow for a request that needed a key but named none. Grants the
/// third-party scope set on the chosen key, then replays the original request
/// so the caller receives what it actually asked for.
fn handle_any_access_then_replay_response(
    ctx: &mut dyn DelegateEnv,
    user_resp: &freenet_stdlib::prelude::UserInputResponse<'_>,
    requestor: SignatureRequestor,
    fingerprints: Vec<String>,
    original_payload: Vec<u8>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let choices = key_choices(ctx, &fingerprints);
    let fp = match match_offered_fingerprint(user_resp.response.bytes(), &choices) {
        AnyAccessChoice::Chose(fp) => fp,
        other => {
            match other {
                AnyAccessChoice::Denied => logging::info("User denied sign-with-default request"),
                _ => logging::info("Sign-with-default response matched no offered fingerprint"),
            }
            let response = ghostkey_common::GhostkeyResponse::AccessDenied { requestor };
            let response_bytes = to_cbor(&response)
                .map_err(|e| DelegateError::Other(format!("serialize response: {e}")))?;
            return Ok(vec![OutboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(response_bytes),
            )]);
        }
    };

    logging::info(&format!(
        "User approved sign-with-default: granting third-party scopes on {fp}"
    ));
    permissions::grant_third_party(ctx, &fp, &requestor);

    // Replay. `resolve_default` will now find this key, because the grant
    // above gives the caller `Sign` on it.
    let request: GhostkeyRequest = from_cbor(&original_payload)
        .map_err(|e| DelegateError::Other(format!("deserialize original request: {e}")))?;
    let response = handlers::handle(ctx, request, &requestor);

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
        let replay = PendingPrompt::AnyAccessThenReplay {
            request_id: 9,
            requestor: webapp(0xef),
            fingerprints: vec!["fp1".into(), "fp2".into()],
            original_payload: vec![4, 5, 6],
        };
        let export = PendingPrompt::ExportConfirm {
            request_id: 10,
            requestor: webapp(0x12),
            fingerprint: Some("ciQaxxSwKF8".into()),
            original_payload: vec![7, 8, 9],
        };
        for variant in [&fp, &any, &replay, &export] {
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
        let replay_json = serde_json::to_string(&replay).unwrap();
        assert!(
            replay_json.starts_with(r#"{"AnyAccessThenReplay":"#),
            "AnyAccessThenReplay variant name shifted: {replay_json}"
        );
        let export_json = serde_json::to_string(&export).unwrap();
        assert!(
            export_json.starts_with(r#"{"ExportConfirm":"#),
            "ExportConfirm variant name shifted: {export_json}"
        );
    }

    use crate::env::MemEnv;
    use ghostkey_common::GhostkeyResponse;

    fn only_response(msgs: &[OutboundDelegateMsg]) -> GhostkeyResponse {
        assert_eq!(msgs.len(), 1, "expected exactly one outbound message");
        match &msgs[0] {
            OutboundDelegateMsg::ApplicationMessage(app) => from_cbor(&app.payload).unwrap(),
            other => panic!("expected an ApplicationMessage, got {other:?}"),
        }
    }

    /// The prompt a dispatch produced, or a panic naming what came back
    /// instead. Used by tests that assert an operation ASKS rather than acts.
    fn only_prompt(msgs: &[OutboundDelegateMsg]) -> (u32, String) {
        assert_eq!(msgs.len(), 1, "expected exactly one outbound message");
        match &msgs[0] {
            OutboundDelegateMsg::RequestUserInput(req) => (
                req.request_id,
                String::from_utf8_lossy(req.message.bytes()).into_owned(),
            ),
            OutboundDelegateMsg::ApplicationMessage(app) => {
                let response: GhostkeyResponse = from_cbor(&app.payload).unwrap();
                panic!("expected a user prompt, got an immediate response: {response:?}")
            }
            other => panic!("expected a user prompt, got {other:?}"),
        }
    }

    fn dispatch_in(
        env: &mut MemEnv,
        request: &GhostkeyRequest,
        requestor: &SignatureRequestor,
    ) -> Vec<OutboundDelegateMsg> {
        let payload = to_cbor(request).unwrap();
        handle_request(env, &payload, requestor).unwrap()
    }

    fn dispatch(request: &GhostkeyRequest) -> Vec<OutboundDelegateMsg> {
        dispatch_in(&mut MemEnv::new(), request, &webapp(0x11))
    }

    /// Answer an in-flight prompt the way the runtime would.
    /// Answer an in-flight prompt the way the runtime would: the id the prompt
    /// was raised under, plus the button the user pressed.
    fn answer(
        env: &mut MemEnv,
        request_id: u32,
        button: &[u8],
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        use freenet_stdlib::prelude::{ClientResponse, UserInputResponse};
        let response = UserInputResponse {
            request_id,
            response: ClientResponse::new(button.to_vec()),
            context: Default::default(),
        };
        handle_user_response(env, &response)
    }

    fn answer_prompt(env: &mut MemEnv, request_id: u32, button: &[u8]) -> Vec<OutboundDelegateMsg> {
        answer(env, request_id, button).unwrap()
    }

    /// A vault holding one ghostkey that `vault` imported, so `vault` holds
    /// the full scope set on it -- `Export` included. Returns the fingerprint.
    fn vault_with_one_key(env: &mut MemEnv, vault: &SignatureRequestor) -> String {
        let (cert, sk) = handlers::test_ghostkey(100);
        handlers::seed_ghostkey(env, &cert, &sk, vault)
    }

    /// Regression: a stored `Export` grant used to be sufficient authority to
    /// extract a raw private signing key. The vault auto-grants itself
    /// `Export` on import, so "the caller holds the grant" says only that some
    /// key was once imported under this identity -- it is not evidence that
    /// the user asked for a backup right now. Export must ask, every time, no
    /// matter who is asking.
    #[test]
    fn export_prompts_even_when_the_caller_already_holds_the_export_grant() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        assert!(
            permissions::has_scope(&env, &fp, &vault, GhostkeyScope::Export),
            "precondition: the importer holds Export, so this is the cached-grant case"
        );

        let msgs = dispatch_in(
            &mut env,
            &GhostkeyRequest::ExportGhostKey {
                fingerprint: fp.clone(),
            },
            &vault,
        );
        let (_, prompt) = only_prompt(&msgs);
        assert!(
            prompt.contains("PRIVATE"),
            "the prompt must say what is leaving the vault: {prompt}"
        );
    }

    /// Same rule for the bulk path, which hands over every private key at once
    /// and would otherwise be the obvious way around a per-key prompt.
    #[test]
    fn export_all_prompts_even_when_the_caller_already_holds_the_export_grant() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        vault_with_one_key(&mut env, &vault);

        let msgs = dispatch_in(&mut env, &GhostkeyRequest::ExportAllGhostKeys, &vault);
        only_prompt(&msgs);
    }

    /// Approving hands over the key -- the prompt is a gate, not a wall.
    #[test]
    fn approving_the_export_prompt_replays_the_export() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        let msgs = dispatch_in(
            &mut env,
            &GhostkeyRequest::ExportGhostKey {
                fingerprint: fp.clone(),
            },
            &vault,
        );
        let (id, _) = only_prompt(&msgs);

        match only_response(&answer_prompt(&mut env, id, b"Allow")) {
            GhostkeyResponse::ExportResult {
                fingerprint,
                signing_key_pem,
                ..
            } => {
                assert_eq!(fingerprint, fp);
                assert!(!signing_key_pem.is_empty());
            }
            other => panic!("expected ExportResult after approval, got {other:?}"),
        }
    }

    /// Denying withholds the key, and -- the part that matters -- approving
    /// once must not be remembered. A grant that survived the prompt would
    /// reduce this to a one-time speed bump.
    #[test]
    fn denying_the_export_prompt_withholds_the_key_and_approval_is_not_cached() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        let export = GhostkeyRequest::ExportGhostKey {
            fingerprint: fp.clone(),
        };

        let (id, _) = only_prompt(&dispatch_in(&mut env, &export, &vault));
        match only_response(&answer_prompt(&mut env, id, b"Deny")) {
            GhostkeyResponse::PermissionDenied { fingerprint, .. } => assert_eq!(fingerprint, fp),
            other => panic!("expected PermissionDenied after denial, got {other:?}"),
        }

        // Approve once...
        let (id, _) = only_prompt(&dispatch_in(&mut env, &export, &vault));
        answer_prompt(&mut env, id, b"Allow");

        // ...and the next export still asks.
        only_prompt(&dispatch_in(&mut env, &export, &vault));
    }

    /// The prompt must not become a way for any app to raise a scary dialog.
    /// A caller with no `Export` grant is refused outright, exactly as before.
    #[test]
    fn export_from_an_ungranted_caller_is_denied_without_a_prompt() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        let msgs = dispatch_in(
            &mut env,
            &GhostkeyRequest::ExportGhostKey { fingerprint: fp },
            &webapp(0x02),
        );
        assert!(
            matches!(
                only_response(&msgs),
                GhostkeyResponse::PermissionDenied { .. }
            ),
            "an app with no Export grant must be refused, not prompted"
        );
    }

    /// `ExportAllGhostKeys` names no fingerprint, so it is never scope-checked
    /// in the dispatcher. A caller that could extract nothing must therefore
    /// get the same empty list it always got, not a dialog.
    #[test]
    fn export_all_from_an_ungranted_caller_answers_empty_without_a_prompt() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        vault_with_one_key(&mut env, &vault);

        let msgs = dispatch_in(
            &mut env,
            &GhostkeyRequest::ExportAllGhostKeys,
            &webapp(0x02),
        );
        match only_response(&msgs) {
            GhostkeyResponse::ExportAllResult { keys } => assert!(keys.is_empty()),
            other => panic!("expected an empty ExportAllResult, got {other:?}"),
        }
    }

    /// `MarkBackedUp` rides on the same `Export` scope but discloses nothing,
    /// and the vault sends it straight after an export. Prompting for it would
    /// mean two dialogs for one user action.
    #[test]
    fn mark_backed_up_does_not_prompt() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        let msgs = dispatch_in(
            &mut env,
            &GhostkeyRequest::MarkBackedUp {
                fingerprint: fp.clone(),
            },
            &vault,
        );
        match only_response(&msgs) {
            GhostkeyResponse::BackedUpMarked { fingerprint } => assert_eq!(fingerprint, fp),
            other => panic!("expected BackedUpMarked, got {other:?}"),
        }
    }

    /// Signing is unaffected: it is revocable, per-message, and already
    /// scoped, so it keeps using the stored grant.
    #[test]
    fn signing_with_a_stored_grant_does_not_prompt() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        let msgs = dispatch_in(
            &mut env,
            &GhostkeyRequest::SignMessage {
                fingerprint: fp,
                message: b"hello".to_vec(),
            },
            &vault,
        );
        assert!(matches!(
            only_response(&msgs),
            GhostkeyResponse::SignResult { .. }
        ));
    }

    /// An export approval must be spendable only on the export it was
    /// collected for. This drives the guard directly, because the delegate
    /// itself never writes a non-export payload into that slot.
    #[test]
    fn an_export_approval_cannot_be_spent_on_another_request() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        let smuggled = to_cbor(&GhostkeyRequest::DeleteGhostKey {
            fingerprint: fp.clone(),
        })
        .unwrap();
        let pending = PendingPrompt::ExportConfirm {
            request_id: 1,
            requestor: vault.clone(),
            fingerprint: Some(fp.clone()),
            original_payload: smuggled,
        };
        env.context_write(&to_cbor(&pending).unwrap());

        assert!(
            matches!(
                only_response(&answer_prompt(&mut env, 1, b"Allow")),
                GhostkeyResponse::PermissionDenied { .. }
            ),
            "an approval collected for an export must not delete a key"
        );
        assert!(
            handlers::load_index(&env).contains(&fp),
            "the key must still be there"
        );
    }

    #[test]
    fn empty_vault_answers_sign_with_default_without_prompting() {
        // End-to-end through the real dispatch, not just the pure router:
        // an empty vault must answer, never raise a picker with no keys in it.
        let msgs = dispatch(&GhostkeyRequest::SignWithDefault {
            message: b"hello".to_vec(),
        });
        assert!(
            matches!(only_response(&msgs), GhostkeyResponse::NoIdentityAvailable),
            "empty vault must still answer NoIdentityAvailable"
        );
    }

    #[test]
    fn get_default_key_never_prompts() {
        // `GetDefaultKey` reports absence as `DefaultKeyResult { None }`, and
        // never raises a picker -- it is a question, and an app must not be
        // able to put a dialog in front of the user just by asking one.
        let msgs = dispatch(&GhostkeyRequest::GetDefaultKey);
        match only_response(&msgs) {
            GhostkeyResponse::DefaultKeyResult { fingerprint } => {
                assert_eq!(fingerprint, None, "empty vault has no default key");
            }
            other => panic!("expected DefaultKeyResult, got {other:?}"),
        }
    }

    #[test]
    fn has_identity_never_prompts_and_reports_an_empty_vault() {
        // The whole point of `HasIdentity` is that an app can ask "is there
        // anything here?" without a consent dialog. A prompt here would make
        // it useless for deciding whether to show a buy-a-key button.
        let msgs = dispatch(&GhostkeyRequest::HasIdentity);
        match only_response(&msgs) {
            GhostkeyResponse::IdentityPresence { usable, unusable } => {
                assert_eq!((usable, unusable), (0, 0));
            }
            other => panic!("expected IdentityPresence, got {other:?}"),
        }
    }

    #[test]
    fn mark_backed_up_from_an_ungranted_app_is_denied_not_prompted() {
        // Prompting would invite the user to click Allow on something the
        // replay still denies, because `Export` is never granted to an app.
        let msgs = dispatch(&GhostkeyRequest::MarkBackedUp {
            fingerprint: "abc123".into(),
        });
        assert!(
            matches!(
                only_response(&msgs),
                GhostkeyResponse::PermissionDenied { .. }
            ),
            "MarkBackedUp must be refused outright for a caller without Export"
        );
    }

    /// An answer only counts for the question it was asked about. There is one
    /// pending-prompt slot per delegate, so a second prompt overwrites the
    /// first while the first is still on screen; without the id check a click
    /// on the visible dialog executes whatever is parked, and the button bytes
    /// overlap (`Allow` serves both a single-key access prompt and an export
    /// confirmation).
    #[test]
    fn a_response_for_a_different_prompt_is_refused() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        let (id, _) = only_prompt(&dispatch_in(
            &mut env,
            &GhostkeyRequest::ExportGhostKey { fingerprint: fp },
            &vault,
        ));

        assert!(
            answer(&mut env, id.wrapping_add(1), b"Allow").is_err(),
            "a response carrying another prompt's id must not be honoured"
        );
    }

    /// The id check is only worth anything if ids differ between invocations.
    /// They come from the secret store precisely because a wasm `static` is
    /// re-initialised on every inbound message, which would hand out the same
    /// id every time and make the check silently vacuous.
    #[test]
    fn prompt_ids_do_not_repeat_across_invocations() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);
        let export = GhostkeyRequest::ExportGhostKey { fingerprint: fp };

        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            let (id, _) = only_prompt(&dispatch_in(&mut env, &export, &vault));
            assert!(seen.insert(id), "prompt id {id} was reused");
        }
    }

    /// The prompt quotes a number; it must be the number of keys the replay
    /// actually hands over, or the dialog described something that did not
    /// happen.
    #[test]
    fn the_export_all_prompt_counts_only_keys_that_can_be_exported() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);

        let whole = vault_with_one_key(&mut env, &vault);
        // A second key whose signing key is gone: listed, looks healthy, and
        // is silently skipped by the export itself.
        let (cert, sk) = handlers::test_ghostkey(50);
        let half = handlers::seed_ghostkey(&mut env, &cert, &sk, &vault);
        env.remove_secret(format!("gk:sk:{half}").as_bytes());

        let (id, prompt) = only_prompt(&dispatch_in(
            &mut env,
            &GhostkeyRequest::ExportAllGhostKeys,
            &vault,
        ));
        assert!(
            !prompt.contains("all 2"),
            "prompt must not promise the half-present key: {prompt}"
        );

        match only_response(&answer_prompt(&mut env, id, b"Allow")) {
            GhostkeyResponse::ExportAllResult { keys } => {
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0].fingerprint, whole);
            }
            other => panic!("expected ExportAllResult, got {other:?}"),
        }
    }

    /// Deleting a ghostkey must take its grants with it, or a fingerprint
    /// re-imported later silently inherits them -- and an export prompt can be
    /// raised for a key the vault no longer holds.
    #[test]
    fn deleting_a_key_drops_its_grants_and_stops_the_export_prompt() {
        let mut env = MemEnv::new();
        let vault = webapp(0x01);
        let fp = vault_with_one_key(&mut env, &vault);

        assert!(matches!(
            only_response(&dispatch_in(
                &mut env,
                &GhostkeyRequest::DeleteGhostKey {
                    fingerprint: fp.clone()
                },
                &vault,
            )),
            GhostkeyResponse::Deleted { .. }
        ));

        assert!(
            !permissions::has_scope(&env, &fp, &vault, GhostkeyScope::Export),
            "grants must not outlive the key"
        );

        // And the export path answers instead of raising a dialog about a key
        // that is gone.
        assert!(matches!(
            only_response(&dispatch_in(
                &mut env,
                &GhostkeyRequest::ExportGhostKey { fingerprint: fp },
                &vault,
            )),
            GhostkeyResponse::PermissionDenied { .. } | GhostkeyResponse::KeyNotFound { .. }
        ));
    }

    #[test]
    fn only_sign_with_default_takes_the_prompt_route() {
        assert!(acts_on_a_key_it_does_not_name(
            &GhostkeyRequest::SignWithDefault {
                message: vec![1, 2, 3]
            }
        ));

        // `GetDefaultKey` names no fingerprint either, but it is a question,
        // not an action. Prompting on it would let any app raise a modal on
        // page load without the user doing anything.
        assert!(!acts_on_a_key_it_does_not_name(
            &GhostkeyRequest::GetDefaultKey
        ));

        // Requests that name a fingerprint must NOT be diverted here -- the
        // scoped check below handles them, and prompting twice for one
        // request would be worse than not prompting at all.
        assert!(!acts_on_a_key_it_does_not_name(
            &GhostkeyRequest::SignMessage {
                fingerprint: "abc".into(),
                message: vec![]
            }
        ));
        assert!(!acts_on_a_key_it_does_not_name(
            &GhostkeyRequest::ListGhostKeys
        ));
        // `RequestAnyAccess` also names no fingerprint, but it is routed
        // earlier to its own picker; diverting it here would double-prompt.
        assert!(!acts_on_a_key_it_does_not_name(
            &GhostkeyRequest::RequestAnyAccess
        ));
        assert!(!acts_on_a_key_it_does_not_name(
            &GhostkeyRequest::HasIdentity
        ));
    }

    #[test]
    fn empty_vault_still_answers_no_identity_available() {
        // The honest case: there is genuinely nothing to prompt about, so the
        // app should be told to send the user to buy a key.
        assert_eq!(
            default_key_route(false, true),
            DefaultKeyRoute::NoIdentity,
            "an empty vault must keep answering NoIdentityAvailable"
        );
    }

    #[test]
    fn keys_present_but_no_grant_prompts_instead_of_denying_existence() {
        // The bug being fixed: this used to answer NoIdentityAvailable, which
        // sends a user who already paid off to buy a second ghostkey.
        assert_eq!(default_key_route(false, false), DefaultKeyRoute::Prompt);
    }

    #[test]
    fn resolvable_default_never_prompts() {
        // Prompting a caller that already holds a grant would mean a consent
        // dialog on every signature.
        assert_eq!(default_key_route(true, false), DefaultKeyRoute::Proceed);
        assert_eq!(default_key_route(true, true), DefaultKeyRoute::Proceed);
    }

    /// Build the `KeyChoice`s a real prompt for these fingerprints and
    /// (already-resolved) display names would have, for tests that only
    /// need to exercise matching, not label resolution.
    fn choices(pairs: &[(&str, &str)]) -> Vec<KeyChoice> {
        let fingerprints: Vec<String> = pairs.iter().map(|(fp, _)| fp.to_string()).collect();
        let names: Vec<String> = pairs.iter().map(|(_, name)| name.to_string()).collect();
        key_choices_from_names(&fingerprints, names)
    }

    #[test]
    fn deny_button_is_a_denial() {
        let offered = choices(&[("fpA", "A"), ("fpB", "B")]);
        assert_eq!(
            match_offered_fingerprint(b"Deny", &offered),
            AnyAccessChoice::Denied
        );
    }

    #[test]
    fn allow_button_selects_the_matching_offered_key() {
        let offered = choices(&[("fpA", "A"), ("fpB", "B")]);
        assert_eq!(
            match_offered_fingerprint(br#"Allow "B""#, &offered),
            AnyAccessChoice::Chose("fpB".to_string())
        );
    }

    #[test]
    fn a_single_offered_key_uses_a_plain_allow_button() {
        // Nothing to disambiguate with only one candidate, so the button
        // (and the match) is just "Allow" -- no name, no fingerprint.
        let offered = choices(&[("fpA", "A")]);
        assert_eq!(
            offered,
            vec![KeyChoice {
                fingerprint: "fpA".to_string(),
                display: "A".to_string(),
                response: b"Allow".to_vec(),
            }]
        );
        assert_eq!(
            match_offered_fingerprint(b"Allow", &offered),
            AnyAccessChoice::Chose("fpA".to_string())
        );
    }

    #[test]
    fn duplicate_display_names_are_disambiguated_by_fingerprint() {
        // Two keys sharing a user-set label (e.g. both named "Work") must
        // not collapse to the same button text -- that would make the
        // second button's click silently grant the first key instead.
        let offered = choices(&[("fpA", "Work"), ("fpB", "Work")]);
        assert_eq!(offered[0].response, br#"Allow "Work (fpA)""#);
        assert_eq!(offered[1].response, br#"Allow "Work (fpB)""#);
        assert_eq!(
            match_offered_fingerprint(&offered[1].response.clone(), &offered),
            AnyAccessChoice::Chose("fpB".to_string())
        );
    }

    #[test]
    fn three_way_label_collision_is_still_disambiguated() {
        // A pathological but reachable case: two keys share a label
        // ("Work"), and a third key's OWN label happens to spell out
        // exactly what the first key's disambiguated name becomes ("Work
        // (fpA)"). A naive "only touch the keys that were originally
        // duplicated" pass leaves fpA and fpC both displaying "Work
        // (fpA)" -- a click meant for fpC would silently grant fpA
        // instead. Every response must come out distinct regardless.
        let offered = choices(&[("fpA", "Work"), ("fpB", "Work"), ("fpC", "Work (fpA)")]);
        let responses: std::collections::HashSet<&Vec<u8>> =
            offered.iter().map(|c| &c.response).collect();
        assert_eq!(
            responses.len(),
            3,
            "all three buttons must have distinct response bytes: {offered:?}"
        );
        for choice in &offered {
            assert_eq!(
                match_offered_fingerprint(&choice.response, &offered),
                AnyAccessChoice::Chose(choice.fingerprint.clone()),
                "each button must round-trip to its own fingerprint, not a collided one"
            );
        }
    }

    #[test]
    fn a_choice_never_offered_cannot_be_selected() {
        // The response arrives from outside the delegate. Parsing the
        // suffix instead of matching the offered list would let a crafted
        // response grant access to a key the user was never shown.
        let offered = choices(&[("fpA", "A"), ("fpB", "B")]);
        assert_eq!(
            match_offered_fingerprint(br#"Allow "Z""#, &offered),
            AnyAccessChoice::Unrecognized
        );
        assert_eq!(
            match_offered_fingerprint(b"Allow \"\"", &offered),
            AnyAccessChoice::Unrecognized
        );
        assert_eq!(
            match_offered_fingerprint(b"", &offered),
            AnyAccessChoice::Unrecognized
        );
        // A single-key-style "Allow" must not match a multi-key offer --
        // there's no key it could unambiguously refer to.
        assert_eq!(
            match_offered_fingerprint(b"Allow", &offered),
            AnyAccessChoice::Unrecognized
        );
        // Prefix of a real button, and the real button plus a suffix.
        assert_eq!(
            match_offered_fingerprint(br#"Allow "A"#, &offered),
            AnyAccessChoice::Unrecognized
        );
        assert_eq!(
            match_offered_fingerprint(br#"Allow "A"" extra"#, &offered),
            AnyAccessChoice::Unrecognized
        );
    }

    #[test]
    fn nothing_can_be_selected_when_nothing_was_offered() {
        assert_eq!(
            match_offered_fingerprint(br#"Allow "A""#, &[]),
            AnyAccessChoice::Unrecognized
        );
        // Deny still works with an empty offer list.
        assert_eq!(
            match_offered_fingerprint(b"Deny", &[]),
            AnyAccessChoice::Denied
        );
    }
}
