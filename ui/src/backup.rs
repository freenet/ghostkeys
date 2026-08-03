//! Tracking which identities the user has a backup of.
//!
//! On most nodes the vault holds the only copy of a ghostkey, and a hosted
//! node reclaims an idle user's entire secret namespace after 30 days, so an
//! identity with no backup is a real way to lose something that cost money.
//!
//! The alternative -- gating the purchase flow on a download -- puts the step
//! at the worst possible moment, when the user is mid-checkout and trying to
//! get back to whatever sent them. It mostly produces a forgotten `.pem` in
//! the Downloads folder of the same machine that runs the node. So instead the
//! vault marks un-backed-up identities and keeps saying so, in the one place
//! where the user is actually looking at something they own.
//!
//! The record lives in `localStorage`, so it is per-browser rather than
//! per-node: storing it in the delegate would change the delegate WASM and
//! therefore re-key it, which is the very thing that loses keys. A second
//! browser will nag again about an identity that is in fact backed up, which
//! is the safe direction to be wrong in.

use std::collections::BTreeSet;

use dioxus::prelude::*;

const BACKED_UP_KEY: &str = "ghostkey_backed_up";

/// Fingerprints the user has exported at least once.
///
/// A signal rather than a direct `localStorage` read so that identity cards
/// re-render the moment a backup completes.
static BACKED_UP: GlobalSignal<BTreeSet<String>> = GlobalSignal::new(load);

/// Parse the stored record. Fingerprints are base58, so a comma separator can
/// never appear inside one and no escaping is needed.
fn parse(stored: &str) -> BTreeSet<String> {
    stored
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn serialize(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(",")
}

fn load() -> BTreeSet<String> {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item(BACKED_UP_KEY).ok().flatten())
            .map(|stored| parse(&stored))
            .unwrap_or_default()
    }
    #[cfg(not(target_arch = "wasm32"))]
    BTreeSet::new()
}

fn persist(set: &BTreeSet<String>) {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            let _ = storage.set_item(BACKED_UP_KEY, &serialize(set));
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = set;
}

/// Whether this identity has been exported at least once.
pub fn is_backed_up(fingerprint: &str) -> bool {
    BACKED_UP.read().contains(fingerprint)
}

/// Record that these identities are now in a backup the user holds.
pub fn mark_backed_up(fingerprints: impl IntoIterator<Item = String>) {
    let mut set = BACKED_UP.write();
    set.extend(fingerprints);
    persist(&set);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_set() {
        let set: BTreeSet<String> = ["aaa".into(), "bbb".into()].into_iter().collect();
        assert_eq!(parse(&serialize(&set)), set);
    }

    #[test]
    fn empty_record_yields_no_fingerprints() {
        assert!(parse("").is_empty());
        assert!(parse(",, ,").is_empty());
    }

    /// A stored record must never report a fingerprint the user has not
    /// actually backed up -- that would silently retire the warning on an
    /// identity that is still the only copy.
    #[test]
    fn parsing_does_not_invent_entries() {
        let parsed = parse("aaa,bbb");
        assert_eq!(parsed.len(), 2);
        assert!(!parsed.contains("ccc"));
    }
}
