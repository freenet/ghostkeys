use freenet_stdlib::client_api::{ClientError, DelegateError, ErrorKind, RequestError};
use freenet_stdlib::prelude::DelegateKey;

// Only the mock/native stubs at the bottom of this file name these directly;
// the wasm implementation imports its own inside `mod real`.
#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
use freenet_stdlib::client_api::HostResponse;
#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
use ghostkey_common::{GhostkeyRequest, GhostkeyResponse};

/// Why a delegate call did not yield a `GhostkeyResponse`.
///
/// This used to be a bare `String`, which collapsed two very different
/// situations into one: "the node told us this delegate does not exist" and
/// "we heard nothing back". Migration has to tell those apart -- the first is
/// a definite *nothing is stored here*, the second means keys may still be
/// stranded under that delegate and we must look again later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegateCallError {
    /// The node reported no such delegate.
    ///
    /// Useful as a fast skip, but NOT proof that nothing is stored under that
    /// delegate, and it must never be treated as such. Two reasons, both
    /// verified in freenet-core: the websocket layer synthesizes this error
    /// from a per-key backoff throttle without ever consulting the delegate
    /// store (`client_events/websocket.rs`), and `UnregisterDelegate` removes
    /// a delegate's code while leaving its secrets in place -- the delegate
    /// store and the secrets store are separate.
    NotRegistered,
    /// The node reported a delegate-level failure (execution error, missing
    /// secret, registration failure). We reached the delegate but the call
    /// did not produce a response.
    Failed(String),
    /// No reply arrived before the deadline. Says nothing about whether the
    /// delegate holds data.
    TimedOut,
    /// The request could not be handed to the node at all.
    Transport(String),
}

impl std::fmt::Display for DelegateCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRegistered => write!(f, "delegate is not registered on this node"),
            Self::Failed(msg) => write!(f, "delegate error: {msg}"),
            Self::TimedOut => write!(f, "timed out waiting for the delegate"),
            Self::Transport(msg) => write!(f, "could not reach the node: {msg}"),
        }
    }
}

/// Name a response variant WITHOUT formatting its payload.
///
/// `GhostkeyResponse` derives `Debug`, and `ExportResult` / `ExportAllResult`
/// carry `signing_key_pem`. So `{response:?}` anywhere on this path would put
/// private keys into the browser console. Every diagnostic here names the
/// variant instead.
pub(crate) fn response_kind(response: &ghostkey_common::GhostkeyResponse) -> &'static str {
    use ghostkey_common::GhostkeyResponse as R;
    match response {
        R::ImportResult { .. } => "ImportResult",
        R::GhostKeyList { .. } => "GhostKeyList",
        R::GhostKeyDetail { .. } => "GhostKeyDetail",
        R::Certificate { .. } => "Certificate",
        R::SignResult { .. } => "SignResult",
        R::DefaultKeyResult { .. } => "DefaultKeyResult",
        R::DefaultKeySet { .. } => "DefaultKeySet",
        R::VerifyResult { .. } => "VerifyResult",
        R::Deleted { .. } => "Deleted",
        R::LabelSet { .. } => "LabelSet",
        R::PermissionGranted { .. } => "PermissionGranted",
        R::PermissionRevoked { .. } => "PermissionRevoked",
        R::PermissionList { .. } => "PermissionList",
        R::ExportResult { .. } => "ExportResult",
        R::ExportAllResult { .. } => "ExportAllResult",
        R::PermissionDenied { .. } => "PermissionDenied",
        R::AccessDenied { .. } => "AccessDenied",
        R::NoIdentityAvailable => "NoIdentityAvailable",
        R::KeyNotFound { .. } => "KeyNotFound",
        R::Error { .. } => "Error",
        // `GhostkeyResponse` is #[non_exhaustive]; a variant from a newer
        // common must still not fall back to a payload-printing Debug.
        _ => "unrecognised response",
    }
}

/// Map a node error onto the delegate call it concerns, when it names one.
///
/// Deliberately narrow. `ExecutionError` and `ForbiddenSecretAccess` carry no
/// delegate key at all, and `RegisterError` names one but corresponds to no
/// waiting call -- `register_delegate` returns as soon as the send succeeds and
/// never enqueues a waiter, so attributing it would resolve some *other*
/// in-flight request for that delegate with a registration failure and leave
/// the queue misaligned from then on. All three are left to the deadline.
///
/// Lives outside the wasm-only module so it can be tested: the
/// `NotRegistered`-vs-anything-else split it produces is what decides whether
/// the migration sweep passes over a delegate or warns the user about it.
pub(crate) fn attribute_error(err: &ClientError) -> Option<(DelegateKey, DelegateCallError)> {
    let ErrorKind::RequestError(RequestError::DelegateError(delegate_error)) = err.kind() else {
        return None;
    };

    match delegate_error {
        DelegateError::Missing(key) => Some((key.clone(), DelegateCallError::NotRegistered)),
        DelegateError::MissingSecret { key, secret } => Some((
            key.clone(),
            DelegateCallError::Failed(format!("missing secret {secret}")),
        )),
        _ => None,
    }
}

// Real implementation: only compiled for WASM without mock features
#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
mod real {
    use std::collections::{HashMap, VecDeque};
    use std::sync::{LazyLock, Mutex};

    use dioxus::logger::tracing::{error, info, warn};
    use freenet_stdlib::client_api::ClientRequest::DelegateOp;
    use freenet_stdlib::client_api::{ClientError, DelegateRequest, HostResponse};
    use freenet_stdlib::prelude::{
        Delegate, DelegateCode, DelegateContainer, DelegateKey, DelegateWasmAPIVersion,
        OutboundDelegateMsg, Parameters,
    };
    use futures::channel::oneshot;
    use futures::future::{select, Either};

    use ghostkey_common::{from_cbor, to_cbor, GhostkeyRequest, GhostkeyResponse};

    use super::DelegateCallError;
    use crate::api::state::WEB_API;

    const DELEGATE_WASM: &[u8] =
        include_bytes!("../../../target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm");

    type PendingReply = Result<GhostkeyResponse, DelegateCallError>;

    struct Waiter {
        token: u64,
        sender: oneshot::Sender<PendingReply>,
    }

    /// In-flight calls to one delegate, oldest first. See `claim_waiter` for
    /// how replies are matched to them and what that cannot handle.
    #[derive(Default)]
    struct DelegateCalls {
        waiters: VecDeque<Waiter>,
    }

    /// Pending calls, keyed by delegate key bytes.
    static PENDING: LazyLock<Mutex<HashMap<Vec<u8>, DelegateCalls>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn next_token() -> u64 {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Hand an arriving reply to the caller that has been waiting longest.
    ///
    /// # The residual this does not solve, and why nothing here tries
    ///
    /// Delegate replies carry no request id (freenet-stdlib carries a standing
    /// TODO for this), so a reply can only be matched to a call by arrival
    /// order. That correspondence breaks when a caller gives up: the node's
    /// late reply is then handed to whoever is waiting next.
    ///
    /// Two attempts were made to compensate in-band and BOTH made things
    /// worse, so the third answer is not to try:
    ///
    /// 1. Counting abandoned replies and discarding that many. The count could
    ///    only be drained by an arriving reply, so a reply that never came left
    ///    it raised forever -- it ate the next call's reply, that call timed
    ///    out and raised it again. One dropped reply wedged the delegate for
    ///    the life of the page.
    /// 2. Giving those abandonments an expiry. The expiry is anchored at the
    ///    give-up instant, the next call is issued immediately, and a healthy
    ///    reply lands ~100ms later -- inside the grace window every time. So
    ///    the entry is drained by the live reply rather than by expiry, and the
    ///    loop sustains itself exactly as before. Simulated: six consecutive
    ///    healthy calls destroyed, no recovery.
    ///
    /// The problem is undecidable from arrival timing: "is this the abandoned
    /// call's reply or the current one's?" has no answer without an id. So the
    /// residual is accepted and bounded instead. It cannot cause lasting harm
    /// here, because nothing durable is derived from it -- the sweep seals
    /// nothing, and the set of keys it skips comes from `ListGhostKeys`, i.e.
    /// the delegate's own state, re-read on every startup. A mis-delivered
    /// reply costs one run's counts, and the next open corrects them.
    ///
    /// A real fix needs request ids on the wire.
    fn claim_waiter(key_bytes: &[u8]) -> Option<oneshot::Sender<PendingReply>> {
        let mut pending = PENDING.lock().ok()?;
        let calls = pending.get_mut(key_bytes)?;
        calls.waiters.pop_front().map(|w| w.sender)
    }

    fn current_delegate_key() -> DelegateKey {
        let delegate_code = DelegateCode::from(DELEGATE_WASM.to_vec());
        let params = Parameters::from(Vec::<u8>::new());
        let delegate = Delegate::from((&delegate_code, &params));
        delegate.key().clone()
    }

    pub fn get_current_delegate_key() -> DelegateKey {
        current_delegate_key()
    }

    pub async fn register_delegate() -> Result<(), String> {
        let delegate_code = DelegateCode::from(DELEGATE_WASM.to_vec());
        let params = Parameters::from(Vec::<u8>::new());
        let delegate = Delegate::from((&delegate_code, &params));
        let container = DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate));

        let api_result = {
            let mut web_api = WEB_API.write();
            if let Some(api) = web_api.as_mut() {
                info!("Registering ghostkey delegate");
                api.send(DelegateOp(DelegateRequest::RegisterDelegate {
                    delegate: container,
                    cipher: DelegateRequest::DEFAULT_CIPHER,
                    nonce: DelegateRequest::DEFAULT_NONCE,
                }))
                .await
            } else {
                Err(freenet_stdlib::client_api::Error::ConnectionClosed)
            }
        };

        match api_result {
            Ok(_) => {
                info!("Ghostkey delegate registered");
                Ok(())
            }
            Err(e) => {
                error!("Failed to register delegate: {e}");
                Err(format!("Failed to register delegate: {e}"))
            }
        }
    }

    /// Send a request to the current ghostkey delegate.
    pub async fn send_request(
        request: GhostkeyRequest,
    ) -> Result<GhostkeyResponse, DelegateCallError> {
        let key = current_delegate_key();
        send_to_delegate(&key, request, 10).await
    }

    /// Send a request to a specific delegate key (for migration).
    ///
    /// What the reply-matching actually depends on: the node answers a given
    /// delegate's requests in the order it received them, and calls to one key
    /// share a deadline. Concurrent calls on one key DO happen -- the sweep
    /// runs in the background while the UI stays interactive -- and FIFO
    /// matching handles that correctly. What it cannot handle is a caller
    /// giving up, since replies carry no id; mixing deadlines on a single key
    /// would make that more likely by letting a later call time out first.
    /// Today the legacy probes (3s) only target legacy keys and `send_request`
    /// (10s) only the current one, so each key stays homogeneous.
    pub async fn send_to_delegate(
        delegate_key: &DelegateKey,
        request: GhostkeyRequest,
        timeout_secs: u64,
    ) -> Result<GhostkeyResponse, DelegateCallError> {
        // Serialize BEFORE registering the pending sender. Bailing out after
        // registration would leave an orphaned sender in the queue, which then
        // absorbs the reply belonging to the NEXT request for this delegate --
        // every subsequent call to it would resolve with the wrong response.
        let payload = to_cbor(&request)
            .map_err(|e| DelegateCallError::Transport(format!("serialize request: {e}")))?;

        let (sender, receiver) = oneshot::channel();
        let key_bytes = delegate_key.encode().into_bytes();
        let token = next_token();

        {
            let mut pending = PENDING
                .lock()
                .map_err(|e| DelegateCallError::Transport(format!("lock poisoned: {e}")))?;
            pending
                .entry(key_bytes.clone())
                .or_default()
                .waiters
                .push_back(Waiter { token, sender });
        }

        let app_msg = freenet_stdlib::prelude::ApplicationMessage::new(payload);
        let delegate_request = DelegateOp(DelegateRequest::ApplicationMessages {
            key: delegate_key.clone(),
            params: Parameters::from(Vec::<u8>::new()),
            inbound: vec![freenet_stdlib::prelude::InboundDelegateMsg::ApplicationMessage(app_msg)],
        });

        let api_result = {
            let mut web_api = WEB_API.write();
            if let Some(api) = web_api.as_mut() {
                api.send(delegate_request).await
            } else {
                Err(freenet_stdlib::client_api::Error::ConnectionClosed)
            }
        };

        if let Err(e) = api_result {
            // The node never received this, so no reply is coming: drop our own
            // waiter and do NOT count it as abandoned. Removing by token rather
            // than by position, so a concurrent call's waiter is never taken.
            if let Ok(mut pending) = PENDING.lock() {
                if let Some(calls) = pending.get_mut(&key_bytes) {
                    calls.waiters.retain(|w| w.token != token);
                }
            }
            return Err(DelegateCallError::Transport(format!("send failed: {e}")));
        }

        let timeout = Box::pin(gloo_timers::future::sleep(std::time::Duration::from_secs(
            timeout_secs,
        )));
        match select(receiver, timeout).await {
            Either::Left((response, _)) => match response {
                Ok(reply) => reply,
                Err(_) => Err(DelegateCallError::Transport(
                    "response channel cancelled".into(),
                )),
            },
            Either::Right((_, _)) => {
                // Give up on this call, removing OUR waiter by token. Popping
                // the front would discard a different call's waiter -- the
                // front is not necessarily ours, since the sweep runs in the
                // background while the UI stays interactive and both talk to
                // the current delegate.
                //
                // Nothing is recorded about the reply that may still be in
                // flight; see `claim_waiter` for why every attempt to
                // compensate for that made things worse.
                if let Ok(mut pending) = PENDING.lock() {
                    if let Some(calls) = pending.get_mut(&key_bytes) {
                        calls.waiters.retain(|w| w.token != token);
                    }
                }
                Err(DelegateCallError::TimedOut)
            }
        }
    }

    pub fn handle_delegate_response(response: &HostResponse) {
        if let HostResponse::DelegateResponse { key, values } = response {
            let key_bytes = key.encode().into_bytes();

            for msg in values {
                if let OutboundDelegateMsg::ApplicationMessage(app_msg) = msg {
                    let gk_response: GhostkeyResponse = match from_cbor(&app_msg.payload) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!("Failed to deserialize delegate response: {e}");
                            continue;
                        }
                    };

                    match claim_waiter(&key_bytes) {
                        Some(sender) => {
                            let _ = sender.send(Ok(gk_response));
                        }
                        None => {
                            warn!("Discarding delegate response with no waiting caller");
                        }
                    }
                }
            }
        }
    }

    /// Resolve the waiting call for a node-reported error.
    ///
    /// Without this, every delegate error was logged to the console and
    /// dropped, so the caller sat on its oneshot until the deadline and then
    /// reported "timed out" for something the node had already explained.
    ///
    /// Scope note, measured rather than assumed: this does NOT speed up probes
    /// for a delegate the node simply does not have. Driving the published
    /// vault against a live node shows those requests draw no response at all,
    /// not an error -- so they still cost a full deadline. What this recovers
    /// is the errors the node *does* send (a throttled key, a missing secret),
    /// which previously vanished into the console.
    pub fn handle_client_error(err: &ClientError) {
        let Some((key, call_error)) = super::attribute_error(err) else {
            // Not attributable to a specific delegate, so there is no way to
            // know which pending request it belongs to. Resolving a guess
            // would fail the wrong call; let the timeout handle it.
            warn!("Unattributable API error: {err}");
            return;
        };

        let key_bytes = key.encode().into_bytes();
        match claim_waiter(&key_bytes) {
            Some(sender) => {
                let _ = sender.send(Err(call_error));
            }
            None => {
                warn!("Discarding delegate error with no waiting caller: {err}");
            }
        }
    }
}

#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
pub use real::{
    get_current_delegate_key, handle_client_error, handle_delegate_response, register_delegate,
    send_request, send_to_delegate,
};

// Stubs for example-data, no-sync, or native compilation
#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
pub async fn register_delegate() -> Result<(), String> {
    Ok(())
}

#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
pub async fn send_request(request: GhostkeyRequest) -> Result<GhostkeyResponse, DelegateCallError> {
    match request {
        GhostkeyRequest::ListGhostKeys => Ok(GhostkeyResponse::GhostKeyList { keys: vec![] }),
        GhostkeyRequest::ImportGhostKey { .. } => Ok(GhostkeyResponse::ImportResult {
            fingerprint: "mock1234".to_string(),
            notary_info: "example_import".into(),
        }),
        // Enough of a key to exercise the export -> confirm -> marked flow
        // offline. The PEM bodies are placeholders; nothing in this path
        // parses them, it only writes them to a file.
        GhostkeyRequest::ExportGhostKey { fingerprint } => Ok(GhostkeyResponse::ExportResult {
            fingerprint,
            certificate_pem:
                "-----BEGIN GHOSTKEY CERTIFICATE-----\nmock\n-----END GHOSTKEY CERTIFICATE-----"
                    .into(),
            signing_key_pem: "-----BEGIN SIGNING KEY-----\nmock\n-----END SIGNING KEY-----".into(),
            label: None,
        }),
        GhostkeyRequest::MarkBackedUp { fingerprint } => {
            Ok(GhostkeyResponse::BackedUpMarked { fingerprint })
        }
        // One identity that cannot sign, so `cargo make dev` shows the warning
        // banner. Reproducing it for real would mean deliberately destroying a
        // signing key.
        GhostkeyRequest::HasIdentity => Ok(GhostkeyResponse::IdentityPresence {
            usable: 3,
            unusable: 1,
        }),
        _ => Ok(GhostkeyResponse::Error {
            message: "Mock mode".into(),
        }),
    }
}

#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
pub fn handle_delegate_response(_response: &HostResponse) {}

#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
pub fn handle_client_error(_err: &ClientError) {}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::{Delegate, DelegateCode, Parameters};

    fn a_delegate_key() -> DelegateKey {
        let code = DelegateCode::from(vec![0u8, 1, 2, 3]);
        let params = Parameters::from(Vec::<u8>::new());
        Delegate::from((&code, &params)).key().clone()
    }

    fn client_error(inner: DelegateError) -> ClientError {
        ErrorKind::RequestError(RequestError::DelegateError(inner)).into()
    }

    /// The distinction the migration sweep turns on: a node that has no such
    /// delegate is passed over, anything else warns the user.
    #[test]
    fn a_missing_delegate_maps_to_not_registered() {
        let key = a_delegate_key();
        let attributed = attribute_error(&client_error(DelegateError::Missing(key.clone())));
        assert_eq!(attributed, Some((key, DelegateCallError::NotRegistered)));
    }

    #[test]
    fn a_missing_secret_is_a_failure_not_an_absent_delegate() {
        let key = a_delegate_key();
        let secret = freenet_stdlib::prelude::SecretsId::new(b"gk:cert:abc".to_vec());
        let attributed =
            attribute_error(&client_error(DelegateError::MissingSecret { key, secret }));
        match attributed {
            Some((_, DelegateCallError::Failed(_))) => {}
            other => panic!("expected a Failed attribution, got {other:?}"),
        }
    }

    /// `register_delegate` never enqueues a waiter, so attributing its failure
    /// would resolve an unrelated in-flight call and misalign the queue from
    /// then on. It must stay unattributed.
    #[test]
    fn a_registration_failure_is_never_attributed() {
        let err = client_error(DelegateError::RegisterError(a_delegate_key()));
        assert_eq!(attribute_error(&err), None);
    }

    /// Errors that name no delegate cannot be matched to a caller; guessing
    /// would fail whichever request happened to be waiting.
    #[test]
    fn errors_without_a_delegate_key_are_not_attributed() {
        let err = client_error(DelegateError::ExecutionError("boom".into()));
        assert_eq!(attribute_error(&err), None);

        let unrelated: ClientError = ErrorKind::NodeUnavailable.into();
        assert_eq!(attribute_error(&unrelated), None);
    }
}
