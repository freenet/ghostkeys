// Only the mock/native stubs at the bottom of this file name these types
// directly; the wasm implementation imports its own inside `mod real`.
#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
use freenet_stdlib::client_api::{ClientError, HostResponse};
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
    /// The node has no such delegate registered. For a legacy delegate this
    /// is conclusive: a delegate the node never registered cannot be holding
    /// secrets, so there is nothing to migrate from it.
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
    use freenet_stdlib::client_api::{
        ClientError, DelegateError, DelegateRequest, ErrorKind, HostResponse, RequestError,
    };
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
    type PendingQueue = VecDeque<oneshot::Sender<PendingReply>>;

    /// Pending responses keyed by delegate key bytes, each with a FIFO queue.
    static PENDING: LazyLock<Mutex<HashMap<Vec<u8>, PendingQueue>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

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

        {
            let mut pending = PENDING
                .lock()
                .map_err(|e| DelegateCallError::Transport(format!("lock poisoned: {e}")))?;
            pending
                .entry(key_bytes.clone())
                .or_insert_with(VecDeque::new)
                .push_back(sender);
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
            if let Ok(mut pending) = PENDING.lock() {
                if let Some(queue) = pending.get_mut(&key_bytes) {
                    queue.pop_back();
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
                if let Ok(mut pending) = PENDING.lock() {
                    if let Some(queue) = pending.get_mut(&key_bytes) {
                        queue.pop_front();
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

                    if let Ok(mut pending) = PENDING.lock() {
                        if let Some(queue) = pending.get_mut(&key_bytes) {
                            if let Some(sender) = queue.pop_front() {
                                let _ = sender.send(Ok(gk_response));
                            } else {
                                warn!("Response for delegate but no pending request");
                            }
                        } else {
                            warn!("Response from unknown delegate key");
                        }
                    }
                }
            }
        }
    }

    /// Resolve the waiting request for a node-reported error.
    ///
    /// Without this every delegate error was logged and dropped, so the caller
    /// sat on its oneshot until the timeout fired -- a request to a delegate
    /// the node does not have took the full timeout to fail and reported
    /// "timed out" rather than "not registered". Migration probes every legacy
    /// delegate, most of which a given node never registered, so that was both
    /// the slow path and the ambiguous one.
    pub fn handle_client_error(err: &ClientError) {
        let Some((key, call_error)) = attribute_error(err) else {
            // Not attributable to a specific delegate, so there is no way to
            // know which pending request it belongs to. Resolving a guess
            // would fail the wrong call; let the timeout handle it.
            warn!("Unattributable API error: {err}");
            return;
        };

        let key_bytes = key.encode().into_bytes();
        if let Ok(mut pending) = PENDING.lock() {
            if let Some(queue) = pending.get_mut(&key_bytes) {
                if let Some(sender) = queue.pop_front() {
                    let _ = sender.send(Err(call_error));
                    return;
                }
            }
        }
        warn!("Delegate error with no pending request: {err}");
    }

    /// Map a node error onto the delegate it concerns, when it names one.
    ///
    /// `ExecutionError` and `ForbiddenSecretAccess` carry no delegate key, so
    /// they are deliberately left unattributed rather than resolved against
    /// whichever request happens to be at the front of some queue.
    fn attribute_error(err: &ClientError) -> Option<(DelegateKey, DelegateCallError)> {
        let ErrorKind::RequestError(RequestError::DelegateError(delegate_error)) = err.kind()
        else {
            return None;
        };

        match delegate_error {
            DelegateError::Missing(key) => Some((key.clone(), DelegateCallError::NotRegistered)),
            DelegateError::RegisterError(key) => Some((
                key.clone(),
                DelegateCallError::Failed("delegate registration failed".into()),
            )),
            DelegateError::MissingSecret { key, secret } => Some((
                key.clone(),
                DelegateCallError::Failed(format!("missing secret {secret}")),
            )),
            _ => None,
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
