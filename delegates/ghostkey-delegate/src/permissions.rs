use freenet_stdlib::prelude::DelegateCtx;
use ghostkey_common::{from_cbor, to_cbor, SignatureRequestor};

/// Secret key for storing the permission list for a ghostkey.
fn perm_key(fingerprint: &str) -> Vec<u8> {
    format!("gk:perms:{fingerprint}").into_bytes()
}

/// Check if a requestor has permission to use a ghostkey.
pub fn is_allowed(ctx: &DelegateCtx, fingerprint: &str, requestor: &SignatureRequestor) -> bool {
    let key = perm_key(fingerprint);
    match ctx.get_secret(&key) {
        Some(bytes) => {
            let allowed: Vec<SignatureRequestor> = from_cbor(&bytes).unwrap_or_default();
            allowed.contains(requestor)
        }
        None => false,
    }
}

/// Grant a requestor permission to use a ghostkey.
pub fn grant(ctx: &mut DelegateCtx, fingerprint: &str, requestor: &SignatureRequestor) {
    let key = perm_key(fingerprint);
    let mut allowed: Vec<SignatureRequestor> = ctx
        .get_secret(&key)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default();

    if !allowed.contains(requestor) {
        allowed.push(requestor.clone());
        if let Ok(bytes) = to_cbor(&allowed) {
            ctx.set_secret(&key, &bytes);
        }
    }
}

/// Revoke a requestor's permission to use a ghostkey.
pub fn revoke(ctx: &mut DelegateCtx, fingerprint: &str, requestor: &SignatureRequestor) {
    let key = perm_key(fingerprint);
    let mut allowed: Vec<SignatureRequestor> = ctx
        .get_secret(&key)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default();

    allowed.retain(|r| r != requestor);

    if let Ok(bytes) = to_cbor(&allowed) {
        ctx.set_secret(&key, &bytes);
    }
}

/// List all requestors with permission for a ghostkey.
pub fn list(ctx: &DelegateCtx, fingerprint: &str) -> Vec<SignatureRequestor> {
    let key = perm_key(fingerprint);
    ctx.get_secret(&key)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}
