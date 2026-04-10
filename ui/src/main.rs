mod api;
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
    // Initialize connection on mount
    use_effect(|| {
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
            }
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
