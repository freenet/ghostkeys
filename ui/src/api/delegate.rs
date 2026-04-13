use freenet_stdlib::client_api::HostResponse;
use ghostkey_common::{GhostkeyRequest, GhostkeyResponse};

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
    use freenet_stdlib::client_api::{DelegateRequest, HostResponse};
    use freenet_stdlib::prelude::{
        Delegate, DelegateCode, DelegateContainer, DelegateKey, DelegateWasmAPIVersion,
        OutboundDelegateMsg, Parameters,
    };
    use futures::channel::oneshot;
    use futures::future::{select, Either};

    use ghostkey_common::{from_cbor, to_cbor, GhostkeyRequest, GhostkeyResponse};

    use crate::api::state::WEB_API;

    const DELEGATE_WASM: &[u8] =
        include_bytes!("../../../target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm");

    /// Pending responses keyed by delegate key bytes, each with a FIFO queue.
    static PENDING: LazyLock<Mutex<HashMap<Vec<u8>, VecDeque<oneshot::Sender<GhostkeyResponse>>>>> =
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
    pub async fn send_request(request: GhostkeyRequest) -> Result<GhostkeyResponse, String> {
        let key = current_delegate_key();
        send_to_delegate(&key, request, 10).await
    }

    /// Send a request to a specific delegate key (for migration).
    pub async fn send_to_delegate(
        delegate_key: &DelegateKey,
        request: GhostkeyRequest,
        timeout_secs: u64,
    ) -> Result<GhostkeyResponse, String> {
        let (sender, receiver) = oneshot::channel();
        let key_bytes = delegate_key.encode().into_bytes();

        {
            let mut pending = PENDING.lock().map_err(|e| format!("Lock error: {e}"))?;
            pending
                .entry(key_bytes.clone())
                .or_insert_with(VecDeque::new)
                .push_back(sender);
        }

        let payload = to_cbor(&request).map_err(|e| format!("Serialize request: {e}"))?;

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
            return Err(format!("Send failed: {e}"));
        }

        let timeout = Box::pin(gloo_timers::future::sleep(std::time::Duration::from_secs(
            timeout_secs,
        )));
        match select(receiver, timeout).await {
            Either::Left((response, _)) => match response {
                Ok(resp) => Ok(resp),
                Err(_) => Err("Response channel cancelled".into()),
            },
            Either::Right((_, _)) => {
                if let Ok(mut pending) = PENDING.lock() {
                    if let Some(queue) = pending.get_mut(&key_bytes) {
                        queue.pop_front();
                    }
                }
                Err("Timeout waiting for delegate response".into())
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
                                let _ = sender.send(gk_response);
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
}

#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
pub use real::{
    get_current_delegate_key, handle_delegate_response, register_delegate, send_request,
    send_to_delegate,
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
pub async fn send_request(request: GhostkeyRequest) -> Result<GhostkeyResponse, String> {
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
