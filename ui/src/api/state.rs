use dioxus::prelude::*;
use freenet_stdlib::client_api::WebApi;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

pub static WEB_API: GlobalSignal<Option<WebApi>> = GlobalSignal::new(|| None);
pub static CONNECTION_STATUS: GlobalSignal<ConnectionStatus> =
    GlobalSignal::new(|| ConnectionStatus::Disconnected);
