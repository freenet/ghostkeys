mod api;
mod auto_import;
mod components;

use dioxus::prelude::*;

use api::connection;
use api::delegate;
use api::state::ConnectionStatus;

const STYLE: Asset = asset!("/assets/style.css");

fn main() {
    launch(App);
}

#[component]
fn App() -> Element {
    use_effect(|| {
        // Set the page title via the shell bridge
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(window) = web_sys::window() {
                if let Ok(Some(parent)) = window.parent() {
                    let msg = js_sys::Object::new();
                    let _ = js_sys::Reflect::set(
                        &msg,
                        &"__freenet_shell__".into(),
                        &wasm_bindgen::JsValue::TRUE,
                    );
                    let _ = js_sys::Reflect::set(&msg, &"type".into(), &"title".into());
                    let _ = js_sys::Reflect::set(&msg, &"title".into(), &"Ghostkey Vault".into());
                    let _ = parent.post_message(&msg, "*");
                }
            }
        }

        spawn(async {
            if let Err(e) = connection::connect().await {
                dioxus::logger::tracing::error!("Connection failed: {e}");
                return;
            }

            // Wait for WebSocket handshake to complete
            for _ in 0..50 {
                if *api::state::CONNECTION_STATUS.read() == ConnectionStatus::Connected {
                    break;
                }
                gloo_timers::future::sleep(std::time::Duration::from_millis(100)).await;
            }

            if *api::state::CONNECTION_STATUS.read() != ConnectionStatus::Connected {
                dioxus::logger::tracing::error!("Timed out waiting for connection");
                return;
            }

            if let Err(e) = delegate::register_delegate().await {
                dioxus::logger::tracing::error!("Delegate registration failed: {e}");
                return;
            }

            // Load existing ghostkeys from delegate storage
            load_ghostkeys().await;

            // Check for auto-import via URL fragment
            auto_import::check_and_import().await;
        });
    });

    let status = api::state::CONNECTION_STATUS.read();

    rsx! {
        document::Stylesheet { href: STYLE }
        div { class: "scene",
            div { class: "scene-grain" }
            header { class: "app-header",
                div { class: "logo-mark" }
                h1 { class: "app-title",
                    span { class: "title-ghost", "Ghost" }
                    span { class: "title-key", "key" }
                }
                p { class: "app-subtitle", "Identity Vault" }
                ConnectionBadge { status: *status }
            }
            main { class: "app-main",
                components::ghostkey_list::GhostKeyList {}
            }
            footer { class: "app-footer",
                "Built: {format_build_time_local()}"
            }
            components::toast::ToastContainer {}
        }
    }
}

const BUILD_TIMESTAMP_ISO: &str = env!("BUILD_TIMESTAMP_ISO", "unknown");

fn format_build_time_local() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        use js_sys::Date;
        let date = Date::new(&wasm_bindgen::JsValue::from_str(BUILD_TIMESTAMP_ISO));
        if date.to_string().as_string().is_some() {
            let year = date.get_full_year();
            let month = date.get_month() + 1;
            let day = date.get_date();
            let hours = date.get_hours();
            let minutes = date.get_minutes();
            let offset_min = date.get_timezone_offset() as i32;
            let tz_str = if offset_min == 0 {
                "UTC".to_string()
            } else {
                let sign = if offset_min <= 0 { '+' } else { '-' };
                let abs = offset_min.unsigned_abs();
                format!("UTC{}{}", sign, abs / 60)
            };
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} {}",
                year, month, day, hours, minutes, tz_str
            )
        } else {
            BUILD_TIMESTAMP_ISO.to_string()
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        BUILD_TIMESTAMP_ISO.to_string()
    }
}

async fn load_ghostkeys() {
    use ghostkey_common::{GhostkeyRequest, GhostkeyResponse};

    match delegate::send_request(GhostkeyRequest::ListGhostKeys).await {
        Ok(GhostkeyResponse::GhostKeyList { keys }) => {
            if !keys.is_empty() {
                dioxus::logger::tracing::info!("Loaded {} ghostkeys from delegate", keys.len());
                for key in keys {
                    components::ghostkey_list::add_ghostkey(key);
                }
            }
        }
        Ok(GhostkeyResponse::Error { message }) => {
            dioxus::logger::tracing::warn!("Failed to load ghostkeys: {message}");
        }
        Ok(_) => {}
        Err(e) => {
            dioxus::logger::tracing::warn!("Failed to load ghostkeys: {e}");
        }
    }
}

#[component]
fn ConnectionBadge(status: ConnectionStatus) -> Element {
    let (class, label) = match status {
        ConnectionStatus::Connected => ("status-badge connected", "Connected"),
        ConnectionStatus::Connecting => ("status-badge connecting", "Connecting..."),
        ConnectionStatus::Disconnected => ("status-badge disconnected", "Disconnected"),
        ConnectionStatus::Error => ("status-badge error", "Error"),
    };

    rsx! {
        div { class: "{class}", "{label}" }
    }
}
