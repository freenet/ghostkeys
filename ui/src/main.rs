mod components;

use dioxus::prelude::*;

const STYLE: Asset = asset!("/assets/style.css");

fn main() {
    launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Stylesheet { href: STYLE }
        div { class: "app-container",
            h1 { "Ghostkey Manager" }
            components::ghostkey_list::GhostKeyList {}
        }
    }
}
