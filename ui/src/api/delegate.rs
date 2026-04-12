use freenet_stdlib::client_api::HostResponse;
use ghostkey_common::{GhostkeyRequest, GhostkeyResponse};

// Real implementation: only compiled for WASM without mock features
#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
mod real {
    use std::collections::VecDeque;
    use std::sync::{LazyLock, Mutex};

    use dioxus::logger::tracing::{error, info, warn};
    use freenet_stdlib::client_api::ClientRequest::DelegateOp;
    use freenet_stdlib::client_api::{DelegateRequest, HostResponse};
    use freenet_stdlib::prelude::{
        Delegate, DelegateCode, DelegateContainer, DelegateWasmAPIVersion, OutboundDelegateMsg,
        Parameters,
    };
    use futures::channel::oneshot;
    use futures::future::{select, Either};

    use ghostkey_common::{from_cbor, to_cbor, GhostkeyRequest, GhostkeyResponse};

    use crate::api::state::WEB_API;

    const DELEGATE_WASM: &[u8] =
        include_bytes!("../../../target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm");

    static PENDING: LazyLock<Mutex<VecDeque<oneshot::Sender<GhostkeyResponse>>>> =
        LazyLock::new(|| Mutex::new(VecDeque::new()));

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

    pub async fn send_request(request: GhostkeyRequest) -> Result<GhostkeyResponse, String> {
        let (sender, receiver) = oneshot::channel();

        {
            let mut pending = PENDING.lock().map_err(|e| format!("Lock error: {e}"))?;
            pending.push_back(sender);
        }

        let payload = to_cbor(&request).map_err(|e| format!("Serialize request: {e}"))?;

        let delegate_code = DelegateCode::from(DELEGATE_WASM.to_vec());
        let params = Parameters::from(Vec::<u8>::new());
        let delegate = Delegate::from((&delegate_code, &params));
        let delegate_key = delegate.key().clone();

        let app_msg = freenet_stdlib::prelude::ApplicationMessage::new(payload);
        let delegate_request = DelegateOp(DelegateRequest::ApplicationMessages {
            key: delegate_key,
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
                pending.pop_back();
            }
            return Err(format!("Send failed: {e}"));
        }

        let timeout = Box::pin(gloo_timers::future::sleep(std::time::Duration::from_secs(
            10,
        )));
        match select(receiver, timeout).await {
            Either::Left((response, _)) => match response {
                Ok(resp) => Ok(resp),
                Err(_) => Err("Response channel cancelled".into()),
            },
            Either::Right((_, _)) => {
                if let Ok(mut pending) = PENDING.lock() {
                    pending.pop_front();
                }
                Err("Timeout waiting for delegate response".into())
            }
        }
    }

    pub fn handle_delegate_response(response: &HostResponse) {
        if let HostResponse::DelegateResponse { values, .. } = response {
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
                        if let Some(sender) = pending.pop_front() {
                            let _ = sender.send(gk_response);
                        } else {
                            warn!("Received delegate response with no pending request");
                        }
                    }
                }
            }
        }
    }
}

// Re-export real implementation on WASM
#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
pub use real::{handle_delegate_response, register_delegate, send_request};

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
