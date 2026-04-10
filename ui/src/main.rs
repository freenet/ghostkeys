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
        div { class: "scene",
            div { class: "scene-grain" }
            header { class: "app-header",
                div { class: "logo-mark" }
                h1 { class: "app-title",
                    span { class: "title-ghost", "Ghost" }
                    span { class: "title-key", "key" }
                }
                p { class: "app-subtitle", "Identity Vault" }
            }
            main { class: "app-main",
                components::ghostkey_list::GhostKeyList {}
            }
        }
    }
}
