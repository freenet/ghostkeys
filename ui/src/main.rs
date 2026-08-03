mod api;
mod auto_import;
mod components;
mod migration;

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
            // Take any import payload off the URL BEFORE anything that can
            // fail. It carries a just-purchased ghostkey that exists nowhere
            // else yet, and each bail-out below used to drop it with nothing
            // but a console line to say so.
            let pending_import = auto_import::pending_import_from_url();

            if let Err(e) = connect_and_register().await {
                dioxus::logger::tracing::error!("Vault startup failed: {e}");
                if pending_import.is_some() {
                    auto_import::warn_not_imported();
                }
                return;
            }

            // Load what the current delegate already holds, so the vault
            // renders immediately and the sweep below knows what it can skip.
            let held = load_ghostkeys().await;
            components::ghostkey_list::load_default_key();

            // Import a just-purchased key BEFORE sweeping legacy delegates.
            // It exists nowhere else, and the sweep can take seconds per
            // legacy entry on a slow node -- there is no reason to make the
            // one irreplaceable key wait behind it.
            if let Some(pending) = pending_import {
                auto_import::import(pending).await;
            }

            // Recover ghostkeys stranded under previous delegate versions.
            migration::try_migrate(held).await;
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

/// Connect to the node and register the current delegate.
///
/// Split out so every failure funnels through one place. As three scattered
/// `return`s it was impossible for the caller to react to a failed startup --
/// which matters because a pending URL import must be reported rather than
/// silently abandoned.
async fn connect_and_register() -> Result<(), String> {
    connection::connect().await?;

    // Wait for the WebSocket handshake to complete.
    for _ in 0..50 {
        if *api::state::CONNECTION_STATUS.read() == ConnectionStatus::Connected {
            break;
        }
        gloo_timers::future::sleep(std::time::Duration::from_millis(100)).await;
    }

    if *api::state::CONNECTION_STATUS.read() != ConnectionStatus::Connected {
        return Err("timed out waiting for the node connection".into());
    }

    delegate::register_delegate().await
}

/// Load the identities the current delegate holds, returning their
/// fingerprints so the legacy sweep can skip what is already here.
///
/// An empty result on failure is the safe direction: the sweep then re-imports
/// rather than wrongly skipping a key it should have recovered.
async fn load_ghostkeys() -> Vec<String> {
    use ghostkey_common::{GhostkeyRequest, GhostkeyResponse};

    match delegate::send_request(GhostkeyRequest::ListGhostKeys).await {
        Ok(GhostkeyResponse::GhostKeyList { keys }) => {
            if keys.is_empty() {
                return Vec::new();
            }
            dioxus::logger::tracing::info!("Loaded {} ghostkeys from delegate", keys.len());
            let fingerprints = keys.iter().map(|k| k.fingerprint.clone()).collect();
            for key in keys {
                components::ghostkey_list::add_ghostkey(key);
            }
            fingerprints
        }
        Ok(GhostkeyResponse::Error { message }) => {
            dioxus::logger::tracing::warn!("Failed to load ghostkeys: {message}");
            Vec::new()
        }
        Ok(_) => Vec::new(),
        Err(e) => {
            dioxus::logger::tracing::warn!("Failed to load ghostkeys: {e}");
            Vec::new()
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
