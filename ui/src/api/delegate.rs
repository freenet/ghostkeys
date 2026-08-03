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

/// Decide whether an arriving reply is owed to a caller that already gave up.
///
/// Expired abandonments are dropped first: a reply that has not arrived within
/// the grace period is treated as lost rather than late. That expiry is the
/// whole point of this function existing. A first version tracked abandonments
/// as a bare count with no expiry, and it wedged the vault permanently the
/// first time a reply never arrived at all -- the count could only be drained
/// by an incoming reply, so it stayed raised, consumed the next call's reply,
/// that call timed out and raised it again, forever. An unattributable error
/// hits exactly that case: it IS the reply, and it is dropped without draining
/// anything.
///
/// Returns true when the caller must discard the reply.
pub(crate) fn take_stale_abandonment(abandoned: &mut Vec<f64>, now: f64) -> bool {
    abandoned.retain(|deadline| *deadline > now);
    if abandoned.is_empty() {
        return false;
    }
    abandoned.remove(0);
    true
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

    /// In-flight calls to one delegate.
    ///
    /// Delegate replies carry no request id (freenet-stdlib has a standing TODO
    /// about this), so a reply can only be matched to a request by position.
    /// That correspondence breaks the moment a caller gives up: the node's late
    /// reply would otherwise be handed to whoever is waiting NOW.
    ///
    /// That is not a cosmetic mix-up here. In the migration sweep it would
    /// resolve one key's `ImportGhostKey` with another key's result, counting a
    /// key as recovered that was never imported.
    #[derive(Default)]
    struct DelegateCalls {
        waiters: VecDeque<Waiter>,
        /// Deadlines (ms since epoch) for replies owed to callers that gave
        /// up. The node answers in request order, so a reply arriving while
        /// one of these is outstanding belongs to the abandoned call and must
        /// be discarded rather than handed to whoever is waiting now.
        ///
        /// They EXPIRE, and that is the whole point. A first version counted
        /// abandonments with no expiry, which wedged the vault permanently the
        /// first time a reply never arrived at all: the count could only be
        /// drained by an incoming reply, so it stayed raised, ate the next
        /// call's reply, that call timed out and raised it again. An
        /// unattributable error is exactly this case -- it IS the reply, and
        /// it is dropped without draining anything.
        ///
        /// So a reply that has not arrived within the grace period is treated
        /// as lost rather than late, and normal service resumes.
        abandoned: Vec<f64>,
    }

    /// How long after giving up a reply may still arrive and be recognised as
    /// stale. Beyond this it is assumed lost. Comfortably longer than any
    /// deadline in use, and bounded so a lost reply costs one grace period
    /// rather than the lifetime of the page.
    const STALE_REPLY_GRACE_MS: f64 = 10_000.0;

    /// Ceiling on outstanding abandonments, so a pathological run cannot grow
    /// this without bound.
    const MAX_ABANDONED: usize = 8;

    /// Pending calls, keyed by delegate key bytes.
    static PENDING: LazyLock<Mutex<HashMap<Vec<u8>, DelegateCalls>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn now_ms() -> f64 {
        js_sys::Date::now()
    }

    fn next_token() -> u64 {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Take the reply that belongs to the next waiter, honouring abandonments
    /// that have not yet expired.
    ///
    /// Returns `None` when the reply belongs to a caller that already gave up
    /// (or to no one at all), in which case it must be dropped.
    fn claim_waiter(key_bytes: &[u8]) -> Option<oneshot::Sender<PendingReply>> {
        let mut pending = PENDING.lock().ok()?;
        let calls = pending.get_mut(key_bytes)?;

        if super::take_stale_abandonment(&mut calls.abandoned, now_ms()) {
            return None;
        }
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
    /// Invariant the reply-matching depends on: at most one call per delegate
    /// key is in flight at a time, and calls to one key all use the same
    /// deadline. Replies carry no request id, so they are matched by arrival
    /// order; mixing deadlines on a single key would let a later call time out
    /// first and cross-deliver an earlier call's reply. Today the legacy
    /// probes (3s) only target legacy keys and `send_request` (10s) only the
    /// current one, which keeps each key homogeneous. If that ever stops being
    /// true, the abandonment bookkeeping needs a per-call identity rather than
    /// a queue position.
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
                // Give up on this call. Remove OUR waiter by token -- popping
                // the front would discard a concurrent call's waiter, and the
                // front is not necessarily ours once deadlines differ.
                //
                // A reply may still be in flight, so record that one incoming
                // reply is owed to a caller who is no longer there -- with an
                // expiry, so a reply that never comes cannot wedge the key.
                if let Ok(mut pending) = PENDING.lock() {
                    if let Some(calls) = pending.get_mut(&key_bytes) {
                        let waiting = calls.waiters.len();
                        calls.waiters.retain(|w| w.token != token);
                        if calls.waiters.len() < waiting && calls.abandoned.len() < MAX_ABANDONED {
                            calls.abandoned.push(now_ms() + STALE_REPLY_GRACE_MS);
                        }
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

    // --- Stale-reply bookkeeping ----------------------------------------

    #[test]
    fn with_nothing_abandoned_a_reply_is_delivered() {
        let mut abandoned = Vec::new();
        assert!(!take_stale_abandonment(&mut abandoned, 1_000.0));
    }

    /// The case the mechanism exists for: a caller gave up, its reply then
    /// arrives, and must not be handed to whoever is waiting now.
    #[test]
    fn a_late_reply_is_discarded_once() {
        let mut abandoned = vec![5_000.0];
        assert!(take_stale_abandonment(&mut abandoned, 1_000.0));
        assert!(abandoned.is_empty(), "one abandonment covers one reply");
        assert!(!take_stale_abandonment(&mut abandoned, 1_000.0));
    }

    /// Regression for a permanent wedge. An abandonment whose reply never
    /// arrives must expire: the previous version could only drain the counter
    /// on an incoming reply, so a lost reply left it raised forever, ate the
    /// next call's reply, and that call's timeout raised it again -- the vault
    /// silently stopped working on a healthy socket until the page reloaded.
    #[test]
    fn an_abandonment_whose_reply_never_arrives_expires() {
        let mut abandoned = vec![5_000.0];

        // Still within the grace period: the reply could genuinely be late.
        assert!(take_stale_abandonment(&mut abandoned.clone(), 4_999.0));

        // Past it: assume lost, and deliver normally again.
        assert!(!take_stale_abandonment(&mut abandoned, 5_001.0));
        assert!(abandoned.is_empty(), "expired entries are dropped");
    }

    /// The wedge was self-sustaining, so pin that it cannot re-establish
    /// itself: repeated give-ups whose replies never arrive must not leave a
    /// backlog that keeps eating live replies.
    #[test]
    fn repeated_lost_replies_do_not_accumulate_into_a_wedge() {
        let mut abandoned = Vec::new();
        let mut clock = 0.0;

        for _ in 0..20 {
            // A call gives up, recording an abandonment that will expire.
            abandoned.push(clock + 10_000.0);
            // Its reply never comes; time passes beyond the grace period.
            clock += 30_000.0;
            // The next call's reply must be delivered, not eaten.
            assert!(
                !take_stale_abandonment(&mut abandoned, clock),
                "a live reply was discarded at t={clock}"
            );
        }
        assert!(abandoned.is_empty());
    }
}
