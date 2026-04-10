use dioxus::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct Toast {
    pub message: String,
    pub kind: ToastKind,
    id: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ToastKind {
    Success,
    Error,
    Info,
}

static TOASTS: GlobalSignal<Vec<Toast>> = GlobalSignal::new(Vec::new);
static TOAST_COUNTER: GlobalSignal<u64> = GlobalSignal::new(|| 0);

pub fn show(message: impl Into<String>, kind: ToastKind) {
    let id = {
        let mut c = TOAST_COUNTER.write();
        *c += 1;
        *c
    };
    TOASTS.write().push(Toast {
        message: message.into(),
        kind,
        id,
    });

    // Auto-dismiss after 5 seconds
    spawn(async move {
        gloo_timers::future::sleep(std::time::Duration::from_secs(5)).await;
        TOASTS.write().retain(|t| t.id != id);
    });
}

#[component]
pub fn ToastContainer() -> Element {
    let toasts = TOASTS.read();

    if toasts.is_empty() {
        return rsx! {};
    }

    rsx! {
        div { class: "toast-container",
            for toast in toasts.iter() {
                ToastItem { toast: toast.clone() }
            }
        }
    }
}

#[component]
fn ToastItem(toast: Toast) -> Element {
    let class = match toast.kind {
        ToastKind::Success => "toast toast-success",
        ToastKind::Error => "toast toast-error",
        ToastKind::Info => "toast toast-info",
    };
    let id = toast.id;

    rsx! {
        div {
            class: "{class}",
            span { "{toast.message}" }
            button {
                class: "toast-close",
                onclick: move |_| TOASTS.write().retain(|t| t.id != id),
                "\u{00d7}"
            }
        }
    }
}
