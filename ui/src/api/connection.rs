use super::state::{ConnectionStatus, CONNECTION_STATUS};

#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
mod real {
    use super::*;
    use dioxus::logger::tracing::{error, info, warn};
    use freenet_stdlib::client_api::{ClientError, HostResponse, WebApi};

    use crate::api::delegate::handle_delegate_response;
    use crate::api::state::WEB_API;

    /// Derive the WebSocket URL from the current page location.
    /// The Freenet gateway serves the WebSocket at /v1/contract/command.
    /// The shell page's postMessage bridge handles auth token injection.
    fn get_websocket_url() -> String {
        const FALLBACK: &str = "ws://localhost:7509/v1/contract/command?encodingProtocol=native";

        if let Some(window) = web_sys::window() {
            let location = window.location();
            let protocol = location.protocol().unwrap_or_default();
            let host = location.host().unwrap_or_default();

            let ws_protocol = if protocol == "https:" { "wss:" } else { "ws:" };
            format!("{ws_protocol}//{host}/v1/contract/command?encodingProtocol=native")
        } else {
            FALLBACK.to_string()
        }
    }

    pub async fn connect() -> Result<(), String> {
        *CONNECTION_STATUS.write() = ConnectionStatus::Connecting;

        let url = get_websocket_url();
        info!("Connecting to Freenet node at {url}");

        let websocket = web_sys::WebSocket::new(&url).map_err(|e| {
            *CONNECTION_STATUS.write() = ConnectionStatus::Error;
            format!("Failed to create WebSocket: {e:?}")
        })?;

        let web_api = WebApi::start(
            websocket,
            move |result: Result<HostResponse, ClientError>| match result {
                Ok(response) => {
                    handle_delegate_response(&response);
                }
                Err(e) => {
                    warn!("API error: {e}");
                }
            },
            {
                move |_error| {
                    error!("WebSocket connection lost");
                    *CONNECTION_STATUS.write() = ConnectionStatus::Disconnected;
                }
            },
            {
                move || {
                    info!("Connected to Freenet node");
                    *CONNECTION_STATUS.write() = ConnectionStatus::Connected;
                }
            },
        );

        *WEB_API.write() = Some(web_api);
        Ok(())
    }
}

#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
pub use real::connect;

#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
pub async fn connect() -> Result<(), String> {
    *CONNECTION_STATUS.write() = ConnectionStatus::Connected;
    Ok(())
}
