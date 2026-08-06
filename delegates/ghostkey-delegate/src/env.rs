//! The delegate's runtime environment, behind a trait.
//!
//! Every handler used to take `&DelegateCtx` directly. That made the
//! authorization paths untestable: off wasm, `DelegateCtx`'s secret store is a
//! permanent no-op -- `get_secret` returns `None`, `set_secret` drops the
//! write, `read` returns empty (freenet-stdlib `delegate_host.rs`, the
//! `#[cfg(not(target_family = "wasm"))]` arms). So a native test could only
//! ever exercise an empty vault with no grants in it, which is exactly the
//! case where an authorization bug does not show up. The tests that mattered
//! -- "a stored grant must not be enough to export a private key", "a caller
//! must not be told how many keys it has no grant on" -- could not be written
//! at all.
//!
//! `DelegateEnv` is the same surface `DelegateCtx` already exposes, named so a
//! test double can stand in for it. Production passes the real `DelegateCtx`;
//! tests pass [`MemEnv`], an in-memory store. Nothing else changes: the trait
//! is a pass-through, and `#[delegate]`'s generated entry point still receives
//! the real `DelegateCtx`.

use freenet_stdlib::prelude::DelegateCtx;

/// Persistent encrypted secret storage plus the per-batch context slot the
/// delegate parks an in-flight prompt in.
///
/// The context methods are prefixed `context_` rather than named `read` /
/// `write` / `clear` so a call site can never be ambiguous about whether it
/// is touching durable secrets or the scratch slot that is cleared between
/// message batches.
pub trait DelegateEnv {
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool;
    fn remove_secret(&mut self, key: &[u8]) -> bool;

    /// Read the per-batch context slot. Empty when nothing is parked there.
    fn context_read(&self) -> Vec<u8>;
    /// Replace the per-batch context slot.
    fn context_write(&mut self, data: &[u8]) -> bool;
    /// Empty the per-batch context slot.
    fn context_clear(&mut self) {
        self.context_write(&[]);
    }
}

impl DelegateEnv for DelegateCtx {
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        DelegateCtx::get_secret(self, key)
    }

    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        DelegateCtx::set_secret(self, key, value)
    }

    fn remove_secret(&mut self, key: &[u8]) -> bool {
        DelegateCtx::remove_secret(self, key)
    }

    fn context_read(&self) -> Vec<u8> {
        DelegateCtx::read(self)
    }

    fn context_write(&mut self, data: &[u8]) -> bool {
        DelegateCtx::write(self, data)
    }

    fn context_clear(&mut self) {
        DelegateCtx::clear(self)
    }
}

/// In-memory `DelegateEnv` for tests: a real secret store and a real context
/// slot, so a test can populate a vault, hand out grants, and then assert on
/// what the authorization paths do with them.
#[cfg(test)]
#[derive(Default)]
pub struct MemEnv {
    secrets: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    context: Vec<u8>,
}

#[cfg(test)]
impl MemEnv {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl DelegateEnv for MemEnv {
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.secrets.get(key).cloned()
    }

    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.secrets.insert(key.to_vec(), value.to_vec());
        true
    }

    fn remove_secret(&mut self, key: &[u8]) -> bool {
        self.secrets.remove(key);
        true
    }

    fn context_read(&self) -> Vec<u8> {
        self.context.clone()
    }

    fn context_write(&mut self, data: &[u8]) -> bool {
        self.context = data.to_vec();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_env_round_trips_secrets_and_context() {
        // The double is only useful if it behaves like a store rather than
        // like `DelegateCtx` off wasm, which silently discards everything.
        let mut env = MemEnv::new();
        assert_eq!(env.get_secret(b"k"), None);
        env.set_secret(b"k", b"v");
        assert_eq!(env.get_secret(b"k").as_deref(), Some(&b"v"[..]));
        env.remove_secret(b"k");
        assert_eq!(env.get_secret(b"k"), None);

        assert!(env.context_read().is_empty());
        env.context_write(b"pending");
        assert_eq!(env.context_read(), b"pending");
        env.context_clear();
        assert!(env.context_read().is_empty());
    }
}
