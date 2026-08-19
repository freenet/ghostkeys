//! The ghostkeys half of the `freenet-migrate` differential (freenet-core#2776 §3).
//!
//! Test-only (`#[cfg(test)] mod` in `main.rs`). Nothing here is compiled into
//! the vault, and `ui/src/migration.rs` is not modified.
//!
//! # Why the differential is split across two crates
//!
//! `freenet-migrate` 0.4.0 requires `freenet-stdlib` 0.8; ghostkeys is on 0.6.
//! Cargo will happily resolve both, but the two **cannot be linked into one
//! binary**: `freenet_stdlib::global` exports `#[no_mangle] extern "C"
//! __frnt_set_id` unconditionally in every version, so the link fails with
//! `duplicate symbol: __frnt_set_id`. `ghostkey-common` genuinely needs stdlib
//! types (`SignatureRequestor` carries a `DelegateKey`), so *no* ghostkeys
//! crate can link the migration crate today -- not even as a dev-dependency.
//!
//! That is a finding, not an inconvenience, so the test is built around it
//! rather than hiding it:
//!
//! * this module runs the **shipped ghostkeys sweep** over the fixtures and
//!   records what it observed into `tests/migration-differential/observations.json`;
//! * the `migration-differential` crate (which links `freenet-migrate` and
//!   stdlib 0.8, and nothing of ghostkeys) replays the *same* fixture inputs
//!   through `migrate_delegate_secrets` and compares against that record.
//!
//! The record is recomputed and re-verified on every run of
//! [`the_recorded_observations_match_the_shipped_sweep`], so it cannot rot into
//! a stale copy of behaviour that has since changed.
//!
//! # The oracle is the OUTGOING hand-rolled sweep, not the crate
//!
//! An equivalence test whose expected values come from the new code proves only
//! that the new code agrees with itself. So every judgement here is made by the
//! real, field-proven functions in [`crate::migration`] -- `classify_presence`,
//! `sweep_step`, `classify`, `MigrationOutcome::record_probe`, `record_import`
//! -- called exactly as the hand-rolled `run_pass` called them through v0.3.0
//! (commit f41fbf3). Even the per-predecessor bucket names are *derived from
//! the shipped code's effect* (see [`gk_bucket`]) rather than restated.
//!
//! Since the freenet-migrate adoption, `run_pass` itself is GONE -- the walk
//! lives in `migration_adapter.rs` -- and [`run_ghostkeys_sweep`] below is the
//! frozen transcription of the sweep users actually had, i.e. the baseline the
//! adoption is differenced against (`migration_adapter_differential.rs`). The
//! decision functions it calls are still the live, shipped ones; only the loop
//! wiring is frozen here, pinned by [`the_harness_mirrors_the_outgoing_sweep`].
//!
//! # Fidelity of the fixtures
//!
//! * Predecessor identities are real `legacy_delegates.toml` rows, parsed the
//!   way `ui/build.rs` parses them.
//! * Replies are real `ghostkey_common::GhostkeyResponse` / `DelegateCallError`
//!   values, the same types `send_to_delegate` returns.
//! * The successor store is the delegate's actual secret namespace --
//!   `gk:cert:<fp>`, `gk:sk:<fp>`, `gk:label:<fp>` and the `gk:index` CBOR
//!   fingerprint list (`delegates/ghostkey-delegate/src/handlers.rs`).
//!   `ListGhostKeys` reads the index, so "which secrets are stored" and "which
//!   keys the user can see" are different questions; both are recorded.

use std::collections::{BTreeMap, BTreeSet};

use ghostkey_common::{ExportedGhostKey, GhostkeyResponse, GhostkeyScope, SignatureRequestor};
use serde::{Deserialize, Serialize};

use crate::api::delegate::DelegateCallError;
use crate::migration::{
    classify, classify_presence, sweep_step, MigrationOutcome, PresenceVerdict, ProbeVerdict,
    SweepStep,
};

/// Where the recorded observations live, relative to this crate.
pub(crate) const OBSERVATIONS_PATH: &str = "../tests/migration-differential/observations.json";

// ---------------------------------------------------------------------------
// The legacy registry, read the way build.rs reads it
// ---------------------------------------------------------------------------

/// The real registry file the vault's sweep table is generated from.
const LEGACY_DELEGATES_TOML: &str = include_str!("../../legacy_delegates.toml");

/// One recorded predecessor: exactly the `(delegate_key, code_hash)` pair
/// `ui/build.rs` emits into `LEGACY_DELEGATES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyEntry {
    pub(crate) delegate_key: [u8; 32],
    pub(crate) code_hash: [u8; 32],
}

/// Parse `legacy_delegates.toml` with the same `[[entry]]` / `key = "hex"`
/// reading `ui/build.rs` does, so the fixtures cannot drift from the table the
/// vault actually ships.
pub(crate) fn legacy_entries() -> Vec<LegacyEntry> {
    let mut entries = Vec::new();
    let mut delegate_key: Option<String> = None;
    let mut code_hash: Option<String> = None;

    for line in LEGACY_DELEGATES_TOML.lines() {
        let line = line.trim();
        if line == "[[entry]]" {
            if let (Some(dk), Some(ch)) = (delegate_key.take(), code_hash.take()) {
                entries.push(LegacyEntry {
                    delegate_key: hex32(&dk),
                    code_hash: hex32(&ch),
                });
            }
        } else if let Some(v) = line.strip_prefix("delegate_key = ") {
            delegate_key = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("code_hash = ") {
            code_hash = Some(v.trim_matches('"').to_string());
        }
    }
    if let (Some(dk), Some(ch)) = (delegate_key, code_hash) {
        entries.push(LegacyEntry {
            delegate_key: hex32(&dk),
            code_hash: hex32(&ch),
        });
    }
    entries
}

fn hex32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    assert_eq!(hex.len(), 64, "not a 32-byte hex string: {hex}");
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex digit");
    }
    out
}

/// A raw `(secret key, value)` pair, the shape `fetch_secrets` returns.
type Pair = (Vec<u8>, Vec<u8>);

/// freenet-migrate's completion-marker key prefix, spelled out because this
/// crate cannot link the migration crate (see the module header). The
/// crate-side test asserts this really is the crate's own
/// `PRED_DONE_MARKER_KEY_PREFIX`, so a rename upstream fails rather than
/// quietly turning the stale-marker fixture into an ordinary secret.
const FREENET_MIGRATE_DONE_PREFIX: &[u8] = b"\0freenet-migrate/v1/pred-done:";

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The shared fixture
// ---------------------------------------------------------------------------

/// One ghostkey as a predecessor would hand it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Key {
    pub(crate) fp: String,
    pub(crate) cert: String,
    pub(crate) sk: String,
    pub(crate) label: Option<String>,
}

impl Key {
    pub(crate) fn exported(&self) -> ExportedGhostKey {
        ExportedGhostKey {
            fingerprint: self.fp.clone(),
            certificate_pem: self.cert.clone(),
            signing_key_pem: self.sk.clone(),
            label: self.label.clone(),
            notary_info: "Freenet Notary".to_string(),
        }
    }
}

pub(crate) fn key(fp: &str, label: Option<&str>) -> Key {
    Key {
        fp: fp.to_string(),
        // Real PEM would be armored certificate bytes; the differential never
        // parses them, it only tracks which bytes land where.
        cert: format!("-----BEGIN GHOSTKEY_CERTIFICATE-----{fp}"),
        sk: format!("-----BEGIN ED25519_SIGNING_KEY_V1-----{fp}"),
        label: label.map(str::to_string),
    }
}

/// What one predecessor delegate does when the sweep reaches it.
///
/// This is the single source of inputs. The ghostkeys sweep consumes the
/// `GhostkeyResponse` / `DelegateCallError` values below directly; the crate
/// consumes the SAME values put through the adapter ([`probe_executable_from`]
/// / [`fetch_secrets_from`]) and recorded into the observations file. Neither
/// side gets fixtures of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PredecessorState {
    /// Registered, says it holds keys, hands them over.
    HoldsAndExports(Vec<Key>),
    /// Registered, answers `HasIdentity` with 0 usable / 0 unusable.
    RegisteredButEmpty,
    /// The node reports no such delegate.
    NotRegistered,
    /// No reply to anything. The ordinary case for a delegate this node never
    /// ran: nine legacy entries, nine timeouts (see `migration.rs`'s header).
    Silent,
    /// A delegate-level failure (missing secret, execution error).
    AnswersWithError(&'static str),
    /// Too old to know `HasIdentity`: errors on the presence probe, exports
    /// fine. This is the OLDER half of the real table.
    TooOldButExports(Vec<Key>),
    /// Holds keys, and its secret namespace ALSO still carries a completion
    /// marker from a migration it performed when it was the successor. This is
    /// what the second re-key after adopting the crate looks like, and the
    /// crate documents that such markers must never be swept forward.
    HoldsKeysAndAStaleMigrationMarker(Vec<Key>),
    /// Said it holds identities, then never answered the export -- typically a
    /// confirmation dialog the user missed.
    HoldsThenSilent,
    /// Said it holds identities, then exported nothing. Positive evidence of
    /// keys this vault cannot reach: `ExportAllGhostKeys` silently skips every
    /// key the caller lacks `Export` scope on.
    HoldsThenExportsNothing,
    /// The request never left the browser -- a dead socket, a serialize
    /// failure. Locally produced, so it is not an answer from anything.
    TransportFailure(&'static str),
}

impl PredecessorState {
    /// The reply to `GhostkeyRequest::HasIdentity`.
    pub(crate) fn presence_reply(&self) -> Result<GhostkeyResponse, DelegateCallError> {
        match self {
            Self::HoldsAndExports(keys) | Self::HoldsKeysAndAStaleMigrationMarker(keys) => {
                Ok(GhostkeyResponse::IdentityPresence {
                    usable: keys.len(),
                    unusable: 0,
                })
            }
            Self::RegisteredButEmpty => Ok(GhostkeyResponse::IdentityPresence {
                usable: 0,
                unusable: 0,
            }),
            Self::HoldsThenSilent | Self::HoldsThenExportsNothing => {
                Ok(GhostkeyResponse::IdentityPresence {
                    usable: 1,
                    unusable: 0,
                })
            }
            Self::NotRegistered => Err(DelegateCallError::NotRegistered),
            Self::Silent => Err(DelegateCallError::TimedOut),
            Self::AnswersWithError(m) => Err(DelegateCallError::Failed((*m).to_string())),
            Self::TransportFailure(m) => Err(DelegateCallError::Transport((*m).to_string())),
            Self::TooOldButExports(_) => Ok(GhostkeyResponse::Error {
                message: "Unsupported request variant for this delegate version".into(),
            }),
        }
    }

    /// The reply to `GhostkeyRequest::ExportAllGhostKeys`.
    pub(crate) fn export_reply(&self) -> Result<GhostkeyResponse, DelegateCallError> {
        match self {
            Self::HoldsAndExports(keys)
            | Self::TooOldButExports(keys)
            | Self::HoldsKeysAndAStaleMigrationMarker(keys) => {
                Ok(GhostkeyResponse::ExportAllResult {
                    keys: keys.iter().map(Key::exported).collect(),
                })
            }
            Self::RegisteredButEmpty | Self::HoldsThenExportsNothing => {
                Ok(GhostkeyResponse::ExportAllResult { keys: Vec::new() })
            }
            Self::Silent | Self::HoldsThenSilent => Err(DelegateCallError::TimedOut),
            Self::NotRegistered => Err(DelegateCallError::NotRegistered),
            Self::AnswersWithError(m) => Err(DelegateCallError::Failed((*m).to_string())),
            Self::TransportFailure(m) => Err(DelegateCallError::Transport((*m).to_string())),
        }
    }
}

/// One predecessor in a scenario: a real registry row plus what it does.
#[derive(Debug, Clone)]
pub(crate) struct Predecessor {
    pub(crate) entry: LegacyEntry,
    /// Position in `legacy_delegates.toml`, oldest first. The crate needs a
    /// `generation`; the registry has none, so this is the only ordering
    /// available -- see [`the_registry_has_no_generation_field`].
    pub(crate) generation: u32,
    pub(crate) state: PredecessorState,
}

/// Build a scenario from states, giving each the identity of the real registry
/// row at the same position (oldest first).
pub(crate) fn predecessors(states: Vec<PredecessorState>) -> Vec<Predecessor> {
    let entries = legacy_entries();
    assert!(
        states.len() <= entries.len(),
        "scenario wants {} predecessors, the real registry has {}",
        states.len(),
        entries.len()
    );
    states
        .into_iter()
        .enumerate()
        .map(|(i, state)| Predecessor {
            entry: entries[i],
            generation: i as u32,
            state,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The successor delegate's secret namespace
// ---------------------------------------------------------------------------

pub(crate) fn cert_key(fp: &str) -> Vec<u8> {
    format!("gk:cert:{fp}").into_bytes()
}
pub(crate) fn sk_key(fp: &str) -> Vec<u8> {
    format!("gk:sk:{fp}").into_bytes()
}
pub(crate) fn label_key(fp: &str) -> Vec<u8> {
    format!("gk:label:{fp}").into_bytes()
}
pub(crate) fn perm_key(fp: &str) -> Vec<u8> {
    format!("gk:perms:{fp}").into_bytes()
}
pub(crate) const INDEX_KEY: &[u8] = b"gk:index";

/// One app's grants on one ghostkey. Mirrors the delegate's own
/// `permissions.rs::GrantEntry` (which lives in the delegate crate and is not
/// importable here) field-for-field, so the modelled `gk:perms:` blob has the
/// real shape rather than an invented one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GrantEntry {
    requestor: SignatureRequestor,
    scopes: std::collections::BTreeSet<GhostkeyScope>,
}

/// The vault's own identity, as the delegate sees it. `handle_import` grants
/// the importing requestor the full scope set; the vault is that requestor.
fn vault_requestor() -> SignatureRequestor {
    SignatureRequestor::WebApp(freenet_stdlib::prelude::ContractInstanceId::new([7u8; 32]))
}

/// The scope set `handle_import` grants the importer
/// (`permissions.rs::full_scope_set`).
fn full_scope_set() -> std::collections::BTreeSet<GhostkeyScope> {
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

/// A model of the successor delegate's secret store, laid out exactly as
/// `delegates/ghostkey-delegate/src/handlers.rs` lays it out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Namespace {
    pub(crate) secrets: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Fingerprints whose secrets this successor's storage refuses to write.
    ///
    /// Models a node-side storage failure, which is a property of the STORE
    /// rather than of either implementation -- each surfaces it through its own
    /// interface, which is precisely the divergence being measured. See
    /// [`Namespace::apply_import`] for why the granularity is per-fingerprint.
    pub(crate) failing: BTreeSet<String>,
}

impl Namespace {
    /// Seed the store with keys the current delegate already holds.
    pub(crate) fn with_keys(keys: &[Key]) -> Self {
        let mut ns = Self::default();
        for k in keys {
            assert!(ns.apply_import(k), "seeding must not fail");
        }
        ns
    }

    /// A successor holding a key whose certificate is stale and whose signing
    /// key is gone -- the half-broken state `migration.rs` re-imports to heal.
    pub(crate) fn with_cert_only(fp: &str) -> Self {
        let mut ns = Self::default();
        ns.secrets.insert(cert_key(fp), b"STALE-CERT".to_vec());
        ns.set_index(&[fp.to_string()]);
        // The grant survived too -- it lives in the same store -- which is
        // exactly why the vault LISTS this key and then cannot sign with it.
        ns.secrets.insert(
            perm_key(fp),
            ghostkey_common::to_cbor(&vec![GrantEntry {
                requestor: vault_requestor(),
                scopes: full_scope_set(),
            }])
            .expect("cbor"),
        );
        ns
    }

    pub(crate) fn index(&self) -> Vec<String> {
        self.secrets
            .get(INDEX_KEY)
            .and_then(|b| ghostkey_common::from_cbor::<Vec<String>>(b).ok())
            .unwrap_or_default()
    }

    pub(crate) fn set_index(&mut self, fps: &[String]) {
        self.secrets.insert(
            INDEX_KEY.to_vec(),
            ghostkey_common::to_cbor(&fps.to_vec()).expect("cbor"),
        );
    }

    /// The writes `handle_import` performs (`handlers.rs::handle_import`):
    /// certificate, signing key, label, index, and -- the step a raw-pair copy
    /// has no equivalent of -- `permissions::grant_full` for the importing
    /// requestor.
    ///
    /// Returns whether the delegate would have answered `ImportResult`. Only
    /// the GRANT write is checked by the real handler: it ignores the results
    /// of the certificate and signing-key writes (`handlers.rs` lines 211/214)
    /// and returns an explicit `Error` only when `grant_full` fails
    /// (`handlers.rs:227`). That asymmetry is why storage failure is modelled
    /// per-fingerprint rather than per-secret: a store that rejects one of a
    /// key's secrets rejects them all, and each implementation then surfaces it
    /// through the write IT actually checks.
    pub(crate) fn apply_import(&mut self, k: &Key) -> bool {
        if self.failing.contains(&k.fp) {
            // `grant_full` fails, so the handler reports an error rather than
            // `ImportResult`. Key material may be half-written; the vault is
            // told the import did not take.
            return false;
        }
        self.secrets
            .insert(cert_key(&k.fp), k.cert.as_bytes().to_vec());
        self.secrets.insert(sk_key(&k.fp), k.sk.as_bytes().to_vec());
        if let Some(label) = &k.label {
            self.secrets
                .insert(label_key(&k.fp), label.as_bytes().to_vec());
        }
        let mut index = self.index();
        if !index.contains(&k.fp) {
            index.push(k.fp.clone());
        }
        self.set_index(&index);
        self.secrets.insert(
            perm_key(&k.fp),
            ghostkey_common::to_cbor(&vec![GrantEntry {
                requestor: vault_requestor(),
                scopes: full_scope_set(),
            }])
            .expect("cbor"),
        );
        true
    }

    /// Raw `gk:index` membership. Necessary but NOT sufficient for the key to
    /// appear in the vault -- see [`Namespace::visible`].
    pub(crate) fn indexed(&self) -> BTreeSet<String> {
        self.index().into_iter().collect()
    }

    /// What `ListGhostKeys` actually reports: an indexed fingerprint the
    /// requestor holds `ReadPublic` on. `handle_list` skips every other one
    /// (`handlers.rs:411`), so a key with no grant is a dead entry for that
    /// requestor no matter what the index says.
    pub(crate) fn visible(&self) -> BTreeSet<String> {
        self.indexed()
            .into_iter()
            .filter(|fp| self.grants_read_public(fp))
            .collect()
    }

    /// Whether the vault holds `ReadPublic` on `fp`, decoded from the real
    /// `gk:perms:` blob rather than assumed from the key's presence.
    fn grants_read_public(&self, fp: &str) -> bool {
        self.secrets
            .get(&perm_key(fp))
            .and_then(|b| ghostkey_common::from_cbor::<Vec<GrantEntry>>(b).ok())
            .is_some_and(|grants| {
                grants.iter().any(|g| {
                    g.requestor == vault_requestor()
                        && g.scopes.contains(&GhostkeyScope::ReadPublic)
                })
            })
    }

    /// Fingerprints with BOTH halves present, whatever the index says. A key
    /// here but not in `visible()` is stored and unreachable.
    pub(crate) fn complete_pairs(&self) -> BTreeSet<String> {
        self.secrets
            .keys()
            .filter_map(|k| {
                let s = String::from_utf8(k.clone()).ok()?;
                let fp = s.strip_prefix("gk:cert:")?.to_string();
                self.secrets.contains_key(&sk_key(&fp)).then_some(fp)
            })
            .collect()
    }

    fn to_wire(&self) -> Vec<(String, String)> {
        self.secrets.iter().map(|(k, v)| (hex(k), hex(v))).collect()
    }
}

// ---------------------------------------------------------------------------
// The shipped ghostkeys sweep
// ---------------------------------------------------------------------------

/// The bucket one predecessor landed in, named by the field the SHIPPED
/// `record_probe` incremented. Deriving it from the real function's effect
/// (rather than restating its match) is what keeps this an oracle: change
/// `record_probe` and this moves with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GkBucket {
    /// Answered "I hold nothing"; `sweep_step` said Skip, so no export was even
    /// attempted and no counter moved.
    SkippedEmpty,
    /// Exported at least one key. `record_probe` increments nothing.
    Exported(usize),
    /// A counter moved; this is its field name.
    Counted(&'static str),
}

impl GkBucket {
    fn name(&self) -> String {
        match self {
            GkBucket::SkippedEmpty => "SkippedEmpty".to_string(),
            GkBucket::Exported(n) => format!("Exported({n})"),
            GkBucket::Counted(name) => (*name).to_string(),
        }
    }
}

/// Run the shipped `record_probe` on a fresh outcome and report which counter
/// it moved.
fn gk_bucket(verdict: &ProbeVerdict, had_presence: bool) -> GkBucket {
    if let ProbeVerdict::Exported(keys) = verdict {
        if !keys.is_empty() {
            return GkBucket::Exported(keys.len());
        }
    }
    let mut o = MigrationOutcome::default();
    o.record_probe(verdict, had_presence);
    for (name, n) in [
        ("undetermined", o.undetermined),
        ("answered_with_error", o.answered_with_error),
        ("present_but_unexportable", o.present_but_unexportable),
        ("present_but_silent", o.present_but_silent),
        ("not_registered", o.not_registered),
        ("unsettled_and_empty", o.unsettled_and_empty),
    ] {
        if n > 0 {
            return GkBucket::Counted(name);
        }
    }
    panic!("record_probe moved no counter for {verdict:?} (had_presence={had_presence})")
}

#[derive(Debug)]
pub(crate) struct GkResult {
    pub(crate) per_predecessor: Vec<GkBucket>,
    pub(crate) outcome: MigrationOutcome,
    pub(crate) store: Namespace,
}

impl GkResult {
    pub(crate) fn names(&self) -> Vec<String> {
        self.per_predecessor.iter().map(GkBucket::name).collect()
    }
}

/// One pass of the ghostkeys sweep over `preds`.
///
/// The decisions are the shipped functions; only the loop wiring is
/// re-expressed here, because `run_pass` is wasm-only. The order below is
/// pinned against `migration.rs` by [`the_harness_mirrors_the_shipped_sweep`].
pub(crate) fn run_ghostkeys_sweep(preds: &[Predecessor], mut store: Namespace) -> GkResult {
    // `run_pass` receives the current delegate's fingerprints and whether that
    // listing was trustworthy; the model's index is the listing.
    let mut held: BTreeSet<String> = store.visible();
    let known_held = true;

    let mut outcome = MigrationOutcome::default();
    let mut per_predecessor = Vec::new();

    // The sweep walks LEGACY_DELEGATES in table order -- oldest first -- and
    // never stops early.
    for pred in preds {
        let presence = classify_presence(pred.state.presence_reply());
        let had_presence = match sweep_step(&presence) {
            SweepStep::Skip => {
                per_predecessor.push(GkBucket::SkippedEmpty);
                continue;
            }
            SweepStep::Record => {
                let PresenceVerdict::NoAnswer(verdict) = presence else {
                    unreachable!("only NoAnswer maps to Record")
                };
                per_predecessor.push(gk_bucket(&verdict, false));
                outcome.record_probe(&verdict, false);
                continue;
            }
            SweepStep::Export { had_presence } => had_presence,
        };

        let verdict = classify(pred.state.export_reply());
        per_predecessor.push(gk_bucket(&verdict, had_presence));
        outcome.record_probe(&verdict, had_presence);

        let exported = match verdict {
            ProbeVerdict::Exported(keys) => keys,
            _ => continue,
        };

        for exported_key in &exported {
            // The shipped sweep re-imports even a fingerprint the current
            // delegate already lists, to heal a key whose certificate survived
            // but whose signing key did not.
            let already_held = !known_held || held.contains(&exported_key.fingerprint);
            let k = Key {
                fp: exported_key.fingerprint.clone(),
                cert: exported_key.certificate_pem.clone(),
                sk: exported_key.signing_key_pem.clone(),
                label: exported_key.label.clone(),
            };
            // `run_pass` reads the delegate's reply: an `ImportResult` is a
            // recovery, anything else is a failed import that is counted and
            // WARNED about -- and the sweep moves on to the next entry either
            // way (migration.rs:678-697).
            if store.apply_import(&k) {
                held.insert(k.fp.clone());
                if !already_held {
                    outcome.record_import(true);
                }
            } else if !already_held {
                outcome.record_import(false);
            }
        }
    }

    GkResult {
        per_predecessor,
        outcome,
        store,
    }
}

// ---------------------------------------------------------------------------
// The adapter a ghostkeys adopter would write
// ---------------------------------------------------------------------------

/// The documented mapping from a ghostkeys presence reply to the crate's
/// tri-state `PredecessorSecretsIo::probe_executable`.
///
/// Deliberately the most charitable adapter available: `HasIdentity` is the
/// "cheap no-op" preflight the crate asks for, and any *reply* is treated as
/// proof the predecessor executed.
fn probe_executable_from(
    reply: Result<GhostkeyResponse, DelegateCallError>,
) -> Result<bool, String> {
    match reply {
        // It ran and answered, whatever it said. An old delegate that errors on
        // `HasIdentity` has still proved its WASM executes.
        Ok(_) => Ok(true),
        // The crate's own docs name this case: "the node no longer has it
        // registered" is one of the things `Ok(false)` covers.
        Err(DelegateCallError::NotRegistered) => Ok(false),
        // "no reply within the app's bound".
        Err(DelegateCallError::TimedOut) => Ok(false),
        // It answered, with a delegate-level failure: executable.
        Err(DelegateCallError::Failed(_)) => Ok(true),
        // Never left the browser: a transport error the crate attaches to
        // `Unresponsive`.
        Err(DelegateCallError::Transport(m)) => Err(format!("transport: {m}")),
    }
}

/// The documented mapping from a ghostkeys export reply to `fetch_secrets`.
///
/// Dumps the full namespace the predecessor's keys imply -- certificate,
/// signing key, label AND the `gk:index` list -- so the crate's raw-pair import
/// has everything it could need.
fn fetch_secrets_from(
    reply: Result<GhostkeyResponse, DelegateCallError>,
    stale_marker: bool,
) -> Result<Vec<Pair>, String> {
    match reply {
        Ok(GhostkeyResponse::ExportAllResult { keys }) => {
            let mut pairs: Vec<Pair> = Vec::new();
            let mut index: Vec<String> = Vec::new();
            for k in &keys {
                pairs.push((
                    cert_key(&k.fingerprint),
                    k.certificate_pem.clone().into_bytes(),
                ));
                pairs.push((
                    sk_key(&k.fingerprint),
                    k.signing_key_pem.clone().into_bytes(),
                ));
                if let Some(label) = &k.label {
                    pairs.push((label_key(&k.fingerprint), label.clone().into_bytes()));
                }
                index.push(k.fingerprint.clone());
            }
            if !index.is_empty() {
                pairs.push((
                    INDEX_KEY.to_vec(),
                    ghostkey_common::to_cbor(&index).expect("cbor"),
                ));
            }
            if stale_marker {
                // A whole-namespace dump includes whatever else is in there,
                // including a completion marker the predecessor wrote when IT
                // was the successor of an earlier generation.
                let mut k = FREENET_MIGRATE_DONE_PREFIX.to_vec();
                k.extend_from_slice(&[0x11u8; 32]);
                pairs.push((k, b"1".to_vec()));
            }
            Ok(pairs)
        }
        Ok(other) => Err(format!(
            "unexpected reply: {}",
            crate::api::delegate::response_kind(&other)
        )),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// The recorded observations (the seam between the two crates)
// ---------------------------------------------------------------------------

/// Whether the two implementations reach the same observable outcome, and if
/// not, what kind of divergence it is. Asserted mechanically on the crate side:
/// the stores are equal if and only if this is not `DivergeOutcome`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Agreement {
    /// Same secrets stored, same secrets visible.
    Agree,
    /// The stores agree; the crate cannot express ghostkeys' classification.
    DivergeClassification(String),
    /// Different secrets end up stored or visible. Key loss, or invisible keys.
    DivergeOutcome(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RecordedPredecessor {
    pub(crate) delegate_key: String,
    pub(crate) code_hash: String,
    pub(crate) generation: u32,
    /// What the adapter's `probe_executable` returns for this predecessor.
    pub(crate) probe: Result<bool, String>,
    /// What the adapter's `fetch_secrets` returns, hex-encoded pairs.
    pub(crate) fetch: Result<Vec<(String, String)>, String>,
    /// The bucket the SHIPPED sweep filed this predecessor under.
    pub(crate) ghostkeys_bucket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RecordedScenario {
    pub(crate) name: String,
    pub(crate) what_it_shows: String,
    pub(crate) agreement: Agreement,
    /// The successor's secret namespace before the sweep, hex-encoded.
    pub(crate) initial_store: Vec<(String, String)>,
    /// Secret keys the successor's storage refuses to write, hex-encoded. The
    /// crate side makes its own `set_secret` fail for exactly these.
    pub(crate) failing_secret_keys: Vec<String>,
    pub(crate) predecessors: Vec<RecordedPredecessor>,
    /// What the shipped sweep produced.
    pub(crate) ghostkeys_store: Vec<(String, String)>,
    /// Listable by the vault: indexed AND granted `ReadPublic`.
    pub(crate) ghostkeys_visible: Vec<String>,
    /// Raw `gk:index` membership, which is only half of listability.
    pub(crate) ghostkeys_indexed: Vec<String>,
    pub(crate) ghostkeys_complete_pairs: Vec<String>,
    pub(crate) ghostkeys_recovered: usize,
    pub(crate) ghostkeys_failed_imports: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Observations {
    /// Read by `migration-differential`; regenerated by the ui-side test.
    pub(crate) generated_by: String,
    pub(crate) scenarios: Vec<RecordedScenario>,
}

/// A scenario definition: the inputs, plus what it is there to show.
pub(crate) struct Scenario {
    pub(crate) name: &'static str,
    pub(crate) what_it_shows: &'static str,
    pub(crate) agreement: Agreement,
    pub(crate) initial: Namespace,
    pub(crate) preds: Vec<Predecessor>,
}

/// A successor store whose storage refuses every secret belonging to `fp`.
fn store_rejecting(fp: &str) -> Namespace {
    Namespace {
        failing: BTreeSet::from([fp.to_string()]),
        ..Namespace::default()
    }
}

/// Every scenario, defined once and consumed by both halves of the
/// differential.
pub(crate) fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "predecessor_holds_keys_and_exports_them",
            what_it_shows: "The case the convergent-design claim was thought to rest on. It \
                 does NOT hold against the real delegate: handle_import ends with \
                 permissions::grant_full (handlers.rs:227) and handle_list skips any \
                 fingerprint the requestor lacks ReadPublic on (handlers.rs:411), while a \
                 raw-pair import grants nothing -- and permissions are not in the exported \
                 pairs at all, so no adapter could supply them.",
            agreement: Agreement::DivergeOutcome(
                "raw-pair import grants no permissions, so recovered keys are unlistable".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::HoldsAndExports(vec![
                key("fpA", Some("work")),
                key("fpB", None),
            ])]),
        },
        Scenario {
            name: "predecessor_registered_but_holds_nothing",
            what_it_shows: "Nothing is imported either way. Different mechanics -- ghostkeys \
                 skips before asking for keys, so no private-key dialog fires, while the crate \
                 probes AND fetches -- but the same observable outcome.",
            agreement: Agreement::Agree,
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::RegisteredButEmpty]),
        },
        Scenario {
            name: "predecessor_not_registered",
            what_it_shows: "ghostkeys keeps `not_registered` apart from silence because nothing \
                 ever re-registers legacy code, so keys under it are unreachable permanently. \
                 `probe_executable` is a bool, so the crate cannot.",
            agreement: Agreement::DivergeClassification(
                "not-registered and silence collapse into one Unresponsive".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::NotRegistered]),
        },
        Scenario {
            name: "predecessor_times_out",
            what_it_shows: "Silence is the ORDINARY case -- nine legacy entries, nine timeouts \
                 on a real node. ghostkeys walks past it. Under NewestSnapshotWins the crate \
                 halts the whole walk, so the data-bearing older generation is never probed.",
            agreement: Agreement::DivergeOutcome(
                "NewestSnapshotWins halts the whole walk on the first silence".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![
                PredecessorState::HoldsAndExports(vec![key("fpOld", None)]),
                PredecessorState::Silent,
            ]),
        },
        Scenario {
            name: "predecessor_answers_with_an_error",
            what_it_shows: "An answered failure is positive evidence and reaches the user; \
                 silence must stay quiet. The crate reports both in the same variant.",
            agreement: Agreement::DivergeClassification(
                "an answered failure is reported as Unresponsive, the silence bucket".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::AnswersWithError(
                "missing secret gk:sk:abc",
            )]),
        },
        Scenario {
            name: "multiple_generations_newest_already_has_the_data",
            what_it_shows: "Keys created under two different generations. ghostkeys recovers \
                 both. NewestSnapshotWins stops at the newest data-bearing generation and \
                 strands the older key; Union recovers its bytes but still cannot make it \
                 visible.",
            agreement: Agreement::DivergeOutcome(
                "NewestSnapshotWins strands keys unique to an older generation".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![
                PredecessorState::HoldsAndExports(vec![key("fpOld", None)]),
                PredecessorState::RegisteredButEmpty,
                PredecessorState::HoldsAndExports(vec![key("fpNew", None)]),
            ]),
        },
        Scenario {
            name: "predecessor_gains_data_after_an_empty_answer",
            what_it_shows: "An empty export is not proof of absence -- ExportAllGhostKeys \
                 silently skips keys the caller lacks Export scope on, and the reply carries no \
                 count. ghostkeys therefore re-sweeps every startup; the crate's completion \
                 marker seals the predecessor as done. The crate-side test runs an empty pass \
                 first, then this one.",
            agreement: Agreement::DivergeOutcome(
                "the crate seals an empty predecessor with a marker; the sweep re-probes".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::TooOldButExports(vec![key(
                "fpLate", None,
            )])]),
        },
        Scenario {
            name: "predecessor_carries_a_stale_migration_marker",
            what_it_shows: "What the SECOND re-key after adopting the crate looks like: the \
                 predecessor's namespace still holds the completion marker it wrote when it was \
                 the successor. The crate documents that markers must never be swept forward, \
                 and strips them on import; ghostkeys never sees them at all, because it \
                 migrates through ImportGhostKey rather than copying raw pairs. The marker \
                 strip itself is correct -- the outcome still diverges, for the permission \
                 reason every recovering scenario does.",
            agreement: Agreement::DivergeOutcome(
                "raw-pair import grants no permissions, so recovered keys are unlistable".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::HoldsKeysAndAStaleMigrationMarker(
                vec![key("fpChained", None)],
            )]),
        },
        Scenario {
            name: "a_failed_write_on_the_newest_predecessor",
            what_it_shows: "A storage failure on one key of the NEWEST predecessor. ghostkeys \
                 counts a failed import, warns, and carries on to recover the older \
                 generation. The crate returns Incomplete and sets terminated = true \
                 UNCONDITIONALLY (delegate_migrate.rs:783) -- pinned for Union too by the \
                 crate's own incomplete_newer_halts_before_older_under_both_policies -- so \
                 every older generation is Superseded and nothing is recovered. Switching \
                 policy does not help.",
            agreement: Agreement::DivergeOutcome(
                "one failed write on the newest predecessor Supersedes every older one, \
                 under BOTH policies"
                    .into(),
            ),
            initial: store_rejecting("fpBad"),
            preds: predecessors(vec![
                PredecessorState::HoldsAndExports(vec![key("fpGood", None)]),
                PredecessorState::HoldsAndExports(vec![key("fpBad", None)]),
            ]),
        },
        Scenario {
            name: "predecessor_holds_keys_but_exports_nothing",
            what_it_shows: "The sharpest instance of the marker bug. The predecessor SAYS it \
                 holds identities and then exports none, because this vault has no Export \
                 scope on them. ghostkeys files present_but_unexportable, warns the user, and \
                 re-asks on every startup. The crate cannot tell this from a genuinely empty \
                 predecessor: it records NoData, writes an empty completion marker, and never \
                 asks again even once the scope is granted.",
            agreement: Agreement::DivergeClassification(
                "keys known to exist and be unreachable are recorded as NoData, then sealed".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::HoldsThenExportsNothing]),
        },
        Scenario {
            name: "predecessor_holds_keys_then_goes_silent",
            what_it_shows: "It said it holds identities and then did not hand them over -- the \
                 shape of a missed confirmation dialog. ghostkeys files present_but_silent and \
                 tells the user to reload and allow the prompt. The crate reports the same \
                 Unresponsive it reports for the eleven entries the node simply does not have.",
            agreement: Agreement::DivergeClassification(
                "a predecessor that announced keys and then went quiet is bucketed with \
                 routine absence"
                    .into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::HoldsThenSilent]),
        },
        Scenario {
            name: "the_request_never_left_the_browser",
            what_it_shows: "A local transport failure: nothing was asked, so nothing was \
                 learned. ghostkeys files it with silence deliberately -- warning here would \
                 put a red toast in front of a user whose websocket dropped, on a node that \
                 may hold no legacy delegates at all, while the connection banner already says \
                 so. The crate attaches the error string, so it reads as evidence.",
            agreement: Agreement::DivergeClassification(
                "a local transport failure is reported as though the predecessor answered".into(),
            ),
            initial: Namespace::default(),
            preds: predecessors(vec![PredecessorState::TransportFailure("socket closed")]),
        },
        Scenario {
            name: "successor_holds_a_half_broken_key",
            what_it_shows: "ListGhostKeys reports a key whenever its CERTIFICATE loads and never \
                 checks the signing key, so a cert-only key looks present and cannot sign. \
                 ghostkeys overwrites both halves to heal it; never-clobber keeps the stale \
                 certificate.",
            agreement: Agreement::DivergeOutcome(
                "never-clobber leaves the successor's stale certificate in place".into(),
            ),
            initial: Namespace::with_cert_only("fpA"),
            preds: predecessors(vec![PredecessorState::HoldsAndExports(vec![key(
                "fpA", None,
            )])]),
        },
        Scenario {
            name: "imported_keys_are_visible_to_the_user",
            what_it_shows: "gk:index is a single CBOR secret and ListGhostKeys reads it. The \
                 successor already has one (the user made a key on the new version), so \
                 never-clobber skips the predecessor's index and the recovered key is stored \
                 but invisible.",
            agreement: Agreement::DivergeOutcome(
                "never-clobber skips gk:index, so imported keys stay invisible".into(),
            ),
            initial: Namespace::with_keys(&[key("fpMine", None)]),
            preds: predecessors(vec![PredecessorState::HoldsAndExports(vec![key(
                "fpOld", None,
            )])]),
        },
    ]
}

fn record(scenario: &Scenario) -> RecordedScenario {
    let gk = run_ghostkeys_sweep(&scenario.preds, scenario.initial.clone());
    let buckets = gk.names();
    assert_eq!(
        buckets.len(),
        scenario.preds.len(),
        "every predecessor must be classified"
    );

    RecordedScenario {
        name: scenario.name.to_string(),
        what_it_shows: scenario.what_it_shows.to_string(),
        agreement: scenario.agreement.clone(),
        initial_store: scenario.initial.to_wire(),
        // Every secret a failing fingerprint owns. The crate writes cert / sk /
        // label / index pairs; ghostkeys additionally writes the grant.
        failing_secret_keys: scenario
            .initial
            .failing
            .iter()
            .flat_map(|fp| [cert_key(fp), sk_key(fp), label_key(fp), perm_key(fp)])
            .map(|k| hex(&k))
            .collect(),
        predecessors: scenario
            .preds
            .iter()
            .zip(buckets)
            .map(|(p, bucket)| RecordedPredecessor {
                delegate_key: hex(&p.entry.delegate_key),
                code_hash: hex(&p.entry.code_hash),
                generation: p.generation,
                probe: probe_executable_from(p.state.presence_reply()),
                fetch: fetch_secrets_from(
                    p.state.export_reply(),
                    matches!(
                        p.state,
                        PredecessorState::HoldsKeysAndAStaleMigrationMarker(_)
                    ),
                )
                .map(|pairs| pairs.iter().map(|(k, v)| (hex(k), hex(v))).collect()),
                ghostkeys_bucket: bucket,
            })
            .collect(),
        ghostkeys_store: gk.store.to_wire(),
        ghostkeys_visible: gk.store.visible().into_iter().collect(),
        ghostkeys_indexed: gk.store.indexed().into_iter().collect(),
        ghostkeys_complete_pairs: gk.store.complete_pairs().into_iter().collect(),
        ghostkeys_recovered: gk.outcome.recovered,
        ghostkeys_failed_imports: gk.outcome.failed_imports,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

/// The seam. Recomputes every scenario from the SHIPPED sweep and compares it
/// against the committed record the `migration-differential` crate reads, so
/// that record cannot rot into a stale copy of behaviour that has changed.
#[test]
fn the_recorded_observations_match_the_shipped_sweep() {
    let observed = Observations {
        generated_by: "ui/src/migration_differential.rs (regenerate with \
                       GK_REGENERATE_OBSERVATIONS=1 cargo test -p ghostkey-ui)"
            .to_string(),
        scenarios: scenarios().iter().map(record).collect(),
    };
    let json = serde_json::to_string_pretty(&observed).expect("serialize") + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(OBSERVATIONS_PATH);

    if std::env::var("GK_REGENERATE_OBSERVATIONS").is_ok() {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, &json).expect("write observations");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}. Regenerate with \
             GK_REGENERATE_OBSERVATIONS=1 cargo test -p ghostkey-ui",
            path.display()
        )
    });
    let committed: Observations =
        serde_json::from_str(&committed).expect("the committed observations must parse");
    assert_eq!(
        committed.scenarios, observed.scenarios,
        "the shipped sweep's behaviour no longer matches the recorded observations the \
         migration-differential crate compares against. If the change is intended, \
         regenerate with GK_REGENERATE_OBSERVATIONS=1 cargo test -p ghostkey-ui and re-read \
         the divergence findings -- they may no longer hold."
    );
}

/// **Expected before running:** both keys imported, both visible, one
/// data-bearing export.
#[test]
fn the_sweep_recovers_an_exporting_predecessor() {
    let s = &scenarios()[0];
    let gk = run_ghostkeys_sweep(&s.preds, s.initial.clone());
    assert_eq!(gk.names(), vec!["Exported(2)"]);
    assert_eq!(gk.outcome.recovered, 2);
    assert_eq!(
        gk.store.visible(),
        BTreeSet::from(["fpA".to_string(), "fpB".to_string()])
    );
}

/// **Expected before running:** the sweep walks past silence and still recovers
/// from the older, data-bearing predecessor -- and stays quiet, because silence
/// is the ordinary case on any node that has not run every previous version.
#[test]
fn the_sweep_walks_past_silence() {
    let s = scenarios()
        .into_iter()
        .find(|s| s.name == "predecessor_times_out")
        .expect("scenario");
    let gk = run_ghostkeys_sweep(&s.preds, s.initial.clone());
    assert_eq!(gk.names(), vec!["Exported(1)", "undetermined"]);
    assert_eq!(gk.store.visible(), BTreeSet::from(["fpOld".to_string()]));
    assert!(
        !gk.outcome.needs_user_attention(),
        "silence is the normal case and must stay quiet"
    );
}

/// **Expected before running:** three distinct ghostkeys buckets, of which only
/// the answered failure reaches the user. The crate has one variant for all
/// three; that half is asserted in `migration-differential`.
#[test]
fn an_answered_failure_is_reported_and_silence_is_not() {
    let all = scenarios();
    let err = all
        .iter()
        .find(|s| s.name == "predecessor_answers_with_an_error")
        .expect("scenario");
    let gk = run_ghostkeys_sweep(&err.preds, err.initial.clone());
    assert_eq!(gk.names(), vec!["answered_with_error"]);
    assert!(gk.outcome.needs_user_attention());

    let silent = predecessors(vec![PredecessorState::Silent]);
    let gk_silent = run_ghostkeys_sweep(&silent, Namespace::default());
    assert_eq!(gk_silent.names(), vec!["undetermined"]);
    assert!(!gk_silent.outcome.needs_user_attention());

    let absent = predecessors(vec![PredecessorState::NotRegistered]);
    let gk_absent = run_ghostkeys_sweep(&absent, Namespace::default());
    assert_eq!(gk_absent.names(), vec!["not_registered"]);
    assert!(!gk_absent.outcome.needs_user_attention());
}

/// **Expected before running:** a re-run over the store the previous pass left
/// is a true no-op -- nothing new is announced and the store is byte-identical.
/// ghostkeys achieves this with no completion marker at all.
#[test]
fn a_rerun_over_an_unchanged_store_changes_nothing() {
    let s = &scenarios()[0];
    let first = run_ghostkeys_sweep(&s.preds, s.initial.clone());
    let second = run_ghostkeys_sweep(&s.preds, first.store.clone());
    assert_eq!(second.outcome.recovered, 0, "no double-counting");
    assert_eq!(second.store, first.store, "re-import is idempotent");
}

/// **Expected before running:** the sweep overwrites BOTH halves, replacing the
/// stale certificate, and does not announce a recovery for a key already
/// listed.
#[test]
fn the_sweep_heals_a_half_broken_key() {
    let s = scenarios()
        .into_iter()
        .find(|s| s.name == "successor_holds_a_half_broken_key")
        .expect("scenario");
    let gk = run_ghostkeys_sweep(&s.preds, s.initial.clone());
    assert_eq!(
        gk.store.secrets.get(&cert_key("fpA")).map(|v| v.as_slice()),
        Some(key("fpA", None).cert.as_bytes()),
        "the stale certificate is replaced"
    );
    assert_eq!(
        gk.outcome.recovered, 0,
        "already listed, so healed without announcing a recovery"
    );
}

/// The oracle's integrity check.
///
/// [`run_ghostkeys_sweep`] is the frozen transcription of the OUTGOING
/// hand-rolled sweep (`migration.rs::real::run_pass` as it shipped through
/// v0.3.0, commit f41fbf3) — the walk itself now lives in
/// `migration_adapter.rs`, driven by `freenet-migrate`, and is differenced
/// against this oracle via the committed observations. The transcription must
/// therefore keep calling the same shipped decision functions in the sweep's
/// order, and keep walking the whole table without an early exit; if someone
/// "simplifies" it, the differential quietly stops measuring the behaviour
/// users actually had. (When this test was written the transcription was
/// pinned line-for-line against the then-shipped `run_pass`; that pin ran
/// green until the walk was replaced in the freenet-migrate adoption PR.)
#[test]
fn the_harness_mirrors_the_outgoing_sweep() {
    let src = include_str!("migration_differential.rs");
    const MARKER: &str = "fn run_ghostkeys_sweep(";
    let at = src.find(MARKER).expect("the oracle function");
    let body = &src[at..];
    let body = &body[..body.find("\n}\n").map(|i| i + 3).unwrap_or(body.len())];

    // The call sequence, in order. `find` from a moving offset, so a
    // reordering fails rather than passing on mere presence.
    let mut cursor = 0usize;
    for needle in [
        "classify_presence(pred.state.presence_reply())",
        "sweep_step(&presence)",
        "classify(pred.state.export_reply())",
        "outcome.record_probe(&verdict, had_presence);",
        "store.apply_import(&k)",
        "outcome.record_import(true);",
    ] {
        let found = body[cursor..].find(needle).unwrap_or_else(|| {
            panic!("the oracle transcription no longer contains `{needle}` in the expected order")
        });
        cursor += found + needle.len();
    }

    // The sweep walked the whole table; silence early in the table never
    // stranded anything after it. The oracle must preserve that.
    assert!(
        !body.contains("break"),
        "the oracle must not stop early; the outgoing sweep never did"
    );
}

/// Every `PredecessorState` variant must be constructed by some scenario.
///
/// A variant with a reply mapping but no scenario is a fixture that looks like
/// coverage and is not: its verdict row would be derived by reading the code
/// rather than by running it. Three variants were in exactly that state when
/// this test was added.
#[test]
fn every_predecessor_state_is_exercised_by_a_scenario() {
    let src = include_str!("migration_differential.rs");

    let enum_body = src
        .split("enum PredecessorState {")
        .nth(1)
        .expect("the PredecessorState enum")
        .split("\n}")
        .next()
        .expect("the enum's closing brace");
    let variants: Vec<&str> = enum_body
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.starts_with(|c: char| c.is_ascii_uppercase())
                && (l.ends_with(',') || l.ends_with(')'))
        })
        .map(|l| l.split(['(', ',']).next().expect("variant name"))
        .collect();
    assert!(
        variants.len() >= 9,
        "expected every variant to be scraped, found {variants:?}"
    );

    let scenarios_body = src
        .split("fn scenarios() -> Vec<Scenario> {")
        .nth(1)
        .expect("the scenarios function")
        .split("\nfn record(")
        .next()
        .expect("the end of scenarios()");
    for variant in variants {
        assert!(
            scenarios_body.contains(&format!("PredecessorState::{variant}")),
            "`PredecessorState::{variant}` is defined but no scenario constructs it, so its \
             verdict row is analytically derived rather than tested"
        );
    }
}

/// The registry the vault ships has no generation column, and the crate's
/// `DelegateLineageEntry` requires one. File order is the only ordering
/// available -- and it is not reliably chronological: two rows record a local
/// build and a CI build of the SAME delegate change (the reproducibility gap
/// documented in the file), so at least one pair of "generations" is an
/// invention of the adapter, not a fact about the lineage.
#[test]
fn the_registry_has_no_generation_field() {
    assert!(
        !LEGACY_DELEGATES_TOML.contains("generation"),
        "if a generation column has been added, the adapter's numbering is no longer a guess"
    );
    let entries = legacy_entries();
    // A FLOOR, not an equality. This assertion's job is to prove build.rs read
    // the REAL registry rather than an empty or fixture one; the exact count is
    // not a property of the code under test. It grows by one at every publish,
    // because scripts/record-migration.sh appends an entry and pushes it to
    // main as part of `cargo make publish-ghostkeys` -- so an exact pin turns
    // every publish into a red main. That is not hypothetical: commit eaee7fa
    // ("record the published delegate hash 0d0e2043c524") added the 13th entry
    // and left main failing this test.
    //
    // The floor still catches the failure that matters here (the registry
    // reading as empty or short) and it ratchets: entries are never meant to be
    // removed, which scripts/check-migration.sh enforces against the base
    // branch. Raise it if you want a tighter net; never make it an equality.
    assert!(
        entries.len() >= 13,
        "the real registry, as build.rs reads it: expected at least 13 entries, found {}",
        entries.len()
    );
    assert_eq!(
        entries
            .iter()
            .map(|e| e.delegate_key)
            .collect::<BTreeSet<_>>()
            .len(),
        entries.len(),
        "no duplicate keys"
    );
}
