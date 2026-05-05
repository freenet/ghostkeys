//! Per-fingerprint permission storage.
//!
//! Each ghostkey has a list of grants of the form
//! `{ requestor, scopes }`. The vault auto-grants itself the full scope set
//! when it imports a key. Third-party apps that go through the
//! `RequestAnyAccess` flow are auto-granted only `{ReadPublic, Sign}` on
//! user approval, so they can read the public certificate and sign
//! messages but cannot extract the private key, delete the identity, or
//! manage other apps' grants.
//!
//! The storage format is `Vec<GrantEntry>` keyed by fingerprint. The
//! delegate WASM hash changed when this module replaced the legacy
//! `Vec<SignatureRequestor>` storage, so existing user data flows in
//! through `legacy_delegates.toml`-driven migration: each previously
//! stored ghostkey is re-imported into the new delegate, which calls
//! `grant_full` for the importing requestor, restoring the vault's
//! authority over its own keys.

use std::collections::BTreeSet;

use freenet_stdlib::prelude::DelegateCtx;
use ghostkey_common::{from_cbor, to_cbor, GhostkeyScope, SignatureRequestor};
use serde::{Deserialize, Serialize};

use crate::logging;

/// One app/delegate's permission record for a single ghostkey.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GrantEntry {
    pub requestor: SignatureRequestor,
    pub scopes: BTreeSet<GhostkeyScope>,
}

/// Secret-store key for the permission list of a ghostkey.
fn perm_key(fingerprint: &str) -> Vec<u8> {
    format!("gk:perms:{fingerprint}").into_bytes()
}

fn load(ctx: &DelegateCtx, fingerprint: &str) -> Vec<GrantEntry> {
    let Some(bytes) = ctx.get_secret(&perm_key(fingerprint)) else {
        // No grant entry for this fingerprint -- normal for a freshly
        // imported key before any third-party grant.
        return Vec::new();
    };
    match from_cbor::<Vec<GrantEntry>>(&bytes) {
        Ok(grants) => grants,
        Err(e) => {
            // The bytes exist but don't deserialise as the current
            // schema. In production the new delegate has a different
            // DelegateKey from any predecessor, so its secret store
            // starts empty and this branch can't be reached. Logging
            // here makes it loud if a future change ever shares the
            // secret store across delegate revisions and a stale
            // grant blob appears: the user's permissions would
            // silently default to "no grants" without this warning.
            logging::info(&format!(
                "Failed to decode grants for {fingerprint}: {e}; treating as empty"
            ));
            Vec::new()
        }
    }
}

fn save(ctx: &mut DelegateCtx, fingerprint: &str, grants: &[GrantEntry]) {
    if let Ok(bytes) = to_cbor(&grants.to_vec()) {
        ctx.set_secret(&perm_key(fingerprint), &bytes);
    }
}

/// Every scope the delegate enforces today. Granted to the importing
/// requestor (the vault) so it owns full management authority over its
/// own keys.
pub fn full_scope_set() -> BTreeSet<GhostkeyScope> {
    [
        GhostkeyScope::ReadPublic,
        GhostkeyScope::Sign,
        GhostkeyScope::Export,
        GhostkeyScope::Delete,
        GhostkeyScope::Admin,
    ]
    .into_iter()
    .collect()
}

/// Scope set granted to a third-party app via `RequestAnyAccess` on user
/// approval. Deliberately excludes `Export`, `Delete`, and `Admin` so a
/// `Sign` grant cannot escalate into key theft, identity destruction, or
/// permission-management privileges.
pub fn third_party_scope_set() -> BTreeSet<GhostkeyScope> {
    [GhostkeyScope::ReadPublic, GhostkeyScope::Sign]
        .into_iter()
        .collect()
}

/// Pure check: does `requestor` hold `scope` in the given grant list?
/// Extracted from `has_scope` so the membership logic is unit-testable
/// without a live `DelegateCtx`.
pub fn has_scope_in(
    grants: &[GrantEntry],
    requestor: &SignatureRequestor,
    scope: GhostkeyScope,
) -> bool {
    grants
        .iter()
        .any(|g| &g.requestor == requestor && g.scopes.contains(&scope))
}

/// Pure: produce a new grant list with `scopes` added to `requestor`'s
/// entry (creating the entry if absent). Existing scopes for the same
/// requestor are preserved (set union).
pub fn with_grant(
    mut grants: Vec<GrantEntry>,
    requestor: &SignatureRequestor,
    scopes: BTreeSet<GhostkeyScope>,
) -> Vec<GrantEntry> {
    if let Some(entry) = grants.iter_mut().find(|g| &g.requestor == requestor) {
        entry.scopes.extend(scopes);
    } else {
        grants.push(GrantEntry {
            requestor: requestor.clone(),
            scopes,
        });
    }
    grants
}

/// Pure: produce a new grant list with every grant for `requestor`
/// removed. Other requestors' grants are untouched.
pub fn without_grants_for(
    mut grants: Vec<GrantEntry>,
    requestor: &SignatureRequestor,
) -> Vec<GrantEntry> {
    grants.retain(|g| &g.requestor != requestor);
    grants
}

/// Does `requestor` hold `scope` on `fingerprint`?
pub fn has_scope(
    ctx: &DelegateCtx,
    fingerprint: &str,
    requestor: &SignatureRequestor,
    scope: GhostkeyScope,
) -> bool {
    has_scope_in(&load(ctx, fingerprint), requestor, scope)
}

/// Add `scopes` to the grant for `requestor` on `fingerprint`. Creates the
/// grant entry if the requestor has none yet.
pub fn grant_scopes(
    ctx: &mut DelegateCtx,
    fingerprint: &str,
    requestor: &SignatureRequestor,
    scopes: BTreeSet<GhostkeyScope>,
) {
    let grants = with_grant(load(ctx, fingerprint), requestor, scopes);
    save(ctx, fingerprint, &grants);
}

/// Grant the full scope set. Called from `handle_import` so the vault
/// (the importer) has complete authority over the ghostkey it brought in.
pub fn grant_full(ctx: &mut DelegateCtx, fingerprint: &str, requestor: &SignatureRequestor) {
    grant_scopes(ctx, fingerprint, requestor, full_scope_set());
}

/// Grant the third-party scope set. Called from the `RequestAnyAccess`
/// approval path.
pub fn grant_third_party(ctx: &mut DelegateCtx, fingerprint: &str, requestor: &SignatureRequestor) {
    grant_scopes(ctx, fingerprint, requestor, third_party_scope_set());
}

/// Remove every grant `requestor` holds on `fingerprint`.
pub fn revoke_all(ctx: &mut DelegateCtx, fingerprint: &str, requestor: &SignatureRequestor) {
    let grants = without_grants_for(load(ctx, fingerprint), requestor);
    save(ctx, fingerprint, &grants);
}

/// List the requestors that hold any grant on `fingerprint`. Preserves
/// the wire shape of the existing `PermissionList` response.
pub fn list_requestors(ctx: &DelegateCtx, fingerprint: &str) -> Vec<SignatureRequestor> {
    load(ctx, fingerprint)
        .into_iter()
        .map(|g| g.requestor)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::ContractInstanceId;

    fn webapp(seed: u8) -> SignatureRequestor {
        let bytes = [seed; 32];
        let id = ContractInstanceId::from_bytes(bs58::encode(&bytes).into_string()).unwrap();
        SignatureRequestor::WebApp(id)
    }

    #[test]
    fn has_scope_in_empty_returns_false() {
        let r = webapp(1);
        assert!(!has_scope_in(&[], &r, GhostkeyScope::ReadPublic));
        assert!(!has_scope_in(&[], &r, GhostkeyScope::Sign));
    }

    #[test]
    fn has_scope_in_returns_only_for_matching_requestor_and_scope() {
        let alice = webapp(1);
        let bob = webapp(2);
        let grants = vec![GrantEntry {
            requestor: alice.clone(),
            scopes: [GhostkeyScope::ReadPublic, GhostkeyScope::Sign]
                .into_iter()
                .collect(),
        }];
        assert!(has_scope_in(&grants, &alice, GhostkeyScope::Sign));
        assert!(has_scope_in(&grants, &alice, GhostkeyScope::ReadPublic));
        assert!(!has_scope_in(&grants, &alice, GhostkeyScope::Export));
        assert!(!has_scope_in(&grants, &alice, GhostkeyScope::Delete));
        assert!(!has_scope_in(&grants, &alice, GhostkeyScope::Admin));
        // Bob has no grant at all.
        assert!(!has_scope_in(&grants, &bob, GhostkeyScope::ReadPublic));
    }

    #[test]
    fn third_party_scope_excludes_export_delete_admin() {
        let scopes = third_party_scope_set();
        assert!(scopes.contains(&GhostkeyScope::ReadPublic));
        assert!(scopes.contains(&GhostkeyScope::Sign));
        assert!(!scopes.contains(&GhostkeyScope::Export));
        assert!(!scopes.contains(&GhostkeyScope::Delete));
        assert!(
            !scopes.contains(&GhostkeyScope::Admin),
            "third-party grant must never include Admin -- it would let \
             a granted app escalate by re-granting itself or others"
        );
    }

    #[test]
    fn full_scope_includes_admin() {
        let scopes = full_scope_set();
        assert!(scopes.contains(&GhostkeyScope::Admin));
        // Sanity check: full scope is a strict superset of third-party.
        for s in third_party_scope_set() {
            assert!(scopes.contains(&s));
        }
    }

    #[test]
    fn with_grant_unions_scopes_for_existing_requestor() {
        let alice = webapp(1);
        let initial = vec![GrantEntry {
            requestor: alice.clone(),
            scopes: [GhostkeyScope::ReadPublic].into_iter().collect(),
        }];
        let after = with_grant(initial, &alice, [GhostkeyScope::Sign].into_iter().collect());
        assert_eq!(after.len(), 1);
        assert!(after[0].scopes.contains(&GhostkeyScope::ReadPublic));
        assert!(after[0].scopes.contains(&GhostkeyScope::Sign));
    }

    #[test]
    fn with_grant_appends_for_new_requestor() {
        let alice = webapp(1);
        let bob = webapp(2);
        let initial = vec![GrantEntry {
            requestor: alice.clone(),
            scopes: [GhostkeyScope::ReadPublic].into_iter().collect(),
        }];
        let after = with_grant(initial, &bob, third_party_scope_set());
        assert_eq!(after.len(), 2);
        assert!(has_scope_in(&after, &alice, GhostkeyScope::ReadPublic));
        assert!(has_scope_in(&after, &bob, GhostkeyScope::Sign));
        // Granting Bob mustn't add scopes to Alice.
        assert!(!has_scope_in(&after, &alice, GhostkeyScope::Sign));
    }

    #[test]
    fn without_grants_for_removes_only_named_requestor() {
        let alice = webapp(1);
        let bob = webapp(2);
        let initial = vec![
            GrantEntry {
                requestor: alice.clone(),
                scopes: full_scope_set(),
            },
            GrantEntry {
                requestor: bob.clone(),
                scopes: third_party_scope_set(),
            },
        ];
        let after = without_grants_for(initial, &bob);
        assert_eq!(after.len(), 1);
        assert!(has_scope_in(&after, &alice, GhostkeyScope::Admin));
        assert!(!has_scope_in(&after, &bob, GhostkeyScope::ReadPublic));
    }

    /// Regression: a third-party grant must not let the granted app
    /// upgrade itself to Admin via a subsequent `with_grant` call from
    /// its own context. (`with_grant` is pure -- the gate against this
    /// lives in `handle_grant_permission`'s `Admin` scope check, which
    /// `has_scope_in` here pins.)
    #[test]
    fn third_party_grant_does_not_imply_admin_check_pass() {
        let evil = webapp(99);
        let grants = vec![GrantEntry {
            requestor: evil.clone(),
            scopes: third_party_scope_set(),
        }];
        assert!(!has_scope_in(&grants, &evil, GhostkeyScope::Admin));
    }
}
