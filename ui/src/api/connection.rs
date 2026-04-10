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

    const DEFAULT_GATEWAY_URL: &str = "ws://127.0.0.1:7509";

    fn get_gateway_url() -> String {
        // Check URL query param: ?wsPort=7519
        if let Some(window) = web_sys::window() {
            if let Ok(search) = window.location().search() {
                if let Some(port_param) = search
                    .trim_start_matches('?')
                    .split('&')
                    .find(|p| p.starts_with("wsPort="))
                {
                    if let Some(port) = port_param.strip_prefix("wsPort=") {
                        return format!("ws://127.0.0.1:{port}");
                    }
                }
            }
        }
        DEFAULT_GATEWAY_URL.to_string()
    }

    pub async fn connect() -> Result<(), String> {
        *CONNECTION_STATUS.write() = ConnectionStatus::Connecting;

        let gateway_url = get_gateway_url();
        let auth_token = get_auth_token();
        let url = match &auth_token {
            Some(token) => format!("{gateway_url}?authToken={token}"),
            None => gateway_url,
        };

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

    fn get_auth_token() -> Option<String> {
        let window = web_sys::window()?;
        let token = js_sys::Reflect::get(
            &window,
            &wasm_bindgen::JsValue::from_str("__FREENET_AUTH_TOKEN__"),
        )
        .ok()?;
        token.as_string()
    }
}

#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
pub use real::connect;

// Stub for example-data, no-sync, or native compilation (cargo check on host)
#[cfg(any(
    not(target_family = "wasm"),
    feature = "no-sync",
    feature = "example-data"
))]
pub async fn connect() -> Result<(), String> {
    *CONNECTION_STATUS.write() = ConnectionStatus::Connected;
    Ok(())
}
