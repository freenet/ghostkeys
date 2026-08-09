//! Differential test: ghostkeys' shipped sweep vs `freenet-migrate` 0.4.0.
//!
//! Test-only (`#[cfg(test)] mod` in `main.rs`). Nothing here is compiled into
//! the vault, and nothing in [`crate::migration`] is changed by it.
//!
//! # What this is for
//!
//! freenet-core#2776 §3 proposes porting ghostkeys onto `freenet-migrate`'s
//! delegate half, on the strength of the two having converged on the same
//! probe / classify / import shape independently. This test checks that claim
//! at the level of behaviour rather than structure: one fixture drives both
//! implementations and the observable outcomes are compared.
//!
//! # The oracle is the SHIPPED sweep, not the crate
//!
//! An equivalence test whose expected values come from the new code proves only
//! that the new code agrees with itself. So every judgement on the ghostkeys
//! side is made by the real, field-proven functions in [`crate::migration`] --
//! [`classify_presence`](crate::migration::classify_presence),
//! [`sweep_step`](crate::migration::sweep_step),
//! [`classify`](crate::migration::classify),
//! [`MigrationOutcome::record_probe`](crate::migration::MigrationOutcome::record_probe)
//! and [`record_import`](crate::migration::MigrationOutcome::record_import) --
//! called here exactly as `migration::real::run_pass` calls them. Even the
//! per-predecessor bucket names are *derived from the shipped code's effect*
//! (see [`gk_bucket`]) rather than restated, so a change to `record_probe`
//! moves the oracle automatically instead of leaving a stale copy behind.
//!
//! ## The one honest gap
//!
//! `run_pass` is `#[cfg(target_family = "wasm")]`, so its ~40 lines of loop
//! wiring cannot be called from a native test. [`run_ghostkeys_sweep`] below
//! re-expresses that wiring (only the wiring -- every decision inside it is the
//! shipped function). [`the_harness_mirrors_the_shipped_sweep`] pins the two
//! together by scraping `migration.rs`, in the same style as that file's own
//! `the_sweep_carries_the_default_identity_across`.
//!
//! # Fidelity of the fixtures
//!
//! * Predecessor identities come from the real `legacy_delegates.toml`, parsed
//!   here the way `ui/build.rs` parses it.
//! * Replies are real `ghostkey_common::GhostkeyResponse` /
//!   `DelegateCallError` values, the same types `send_to_delegate` returns.
//! * The successor store is modelled as the delegate's actual secret
//!   namespace -- `gk:cert:<fp>`, `gk:sk:<fp>`, `gk:label:<fp>` and the
//!   `gk:index` CBOR fingerprint list (`delegates/ghostkey-delegate/src/handlers.rs`).
//!   That matters: `ListGhostKeys` reads the index, so "which secrets are in
//!   the store" and "which keys the user can see" are different questions and
//!   the fixtures below answer both.
//!
//! # Findings
//!
//! The agreement/divergence table lives in [`SCENARIOS`], one row per scenario,
//! and [`every_scenario_has_a_declared_agreement`] fails if a new scenario is
//! added without deciding which it is.

use std::collections::{BTreeMap, BTreeSet};

use ghostkey_common::{ExportedGhostKey, GhostkeyResponse};

use crate::api::delegate::DelegateCallError;
use crate::migration::{
    classify, classify_presence, sweep_step, MigrationOutcome, PresenceVerdict, ProbeVerdict,
    SweepStep,
};

// The crate under test. `freenet-stdlib` is pulled in under an alias because
// ghostkeys is pinned to 0.6 and freenet-migrate 0.4.0 requires 0.8 -- see
// `the_crate_forces_a_second_freenet_stdlib_into_the_graph`.
use freenet_migrate::{
    migrate_delegate_secrets, DelegateLineageEntry, MigrationAuthorization, PredecessorMigration,
    PredecessorSecretsIo, SecretPair, SecretSelectionPolicy, SecretStore, UnionAck,
};
use freenet_stdlib_08::prelude::{CodeHash as CodeHash08, DelegateKey as DelegateKey08};

// ---------------------------------------------------------------------------
// The legacy registry, read the way build.rs reads it
// ---------------------------------------------------------------------------

/// The real registry file the vault's sweep table is generated from.
const LEGACY_DELEGATES_TOML: &str = include_str!("../../legacy_delegates.toml");

/// One recorded predecessor: exactly the `(delegate_key, code_hash)` pair
/// `ui/build.rs` emits into `LEGACY_DELEGATES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LegacyEntry {
    delegate_key: [u8; 32],
    code_hash: [u8; 32],
}

/// Parse `legacy_delegates.toml` with the same `[[entry]]` / `key = "hex"`
/// reading `ui/build.rs` does, so the fixtures cannot drift from the table the
/// vault actually ships.
fn legacy_entries() -> Vec<LegacyEntry> {
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

// ---------------------------------------------------------------------------
// The shared fixture
// ---------------------------------------------------------------------------

/// One ghostkey as a predecessor would hand it over.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    fp: &'static str,
    cert: &'static str,
    sk: &'static str,
    label: Option<&'static str>,
}

impl Key {
    fn exported(&self) -> ExportedGhostKey {
        ExportedGhostKey {
            fingerprint: self.fp.to_string(),
            certificate_pem: self.cert.to_string(),
            signing_key_pem: self.sk.to_string(),
            label: self.label.map(str::to_string),
            notary_info: "Freenet Notary".to_string(),
        }
    }
}

fn key(fp: &'static str, label: Option<&'static str>) -> Key {
    Key {
        fp,
        // Real PEM would be armored certificate bytes; the differential never
        // parses them, it only tracks which bytes land where.
        cert: "-----BEGIN GHOSTKEY_CERTIFICATE-----CERT",
        sk: "-----BEGIN ED25519_SIGNING_KEY_V1-----SK",
        label,
    }
}

/// What one predecessor delegate does when the sweep reaches it.
///
/// This is the single source of inputs: both drivers are handed the SAME
/// `(presence_reply, export_reply)` pair produced from this state. Neither side
/// gets fixtures of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PredecessorState {
    /// Registered, says it holds keys, hands them over.
    HoldsAndExports(Vec<Key>),
    /// Registered, answers `HasIdentity` with 0 usable / 0 unusable.
    RegisteredButEmpty,
    /// The node reports no such delegate.
    NotRegistered,
    /// No reply to anything. The ordinary case for a delegate this node never
    /// ran: nine legacy entries, nine timeouts (see `migration.rs`'s header).
    Silent,
    /// Says it holds keys, then never answers the export -- e.g. the user
    /// missed the confirmation dialog.
    HoldsThenSilent,
    /// Says it holds keys, then exports nothing -- keys exist that this vault
    /// has no `Export` scope on.
    HoldsThenExportsNothing,
    /// A delegate-level failure (missing secret, execution error).
    AnswersWithError(&'static str),
    /// Too old to know `HasIdentity`: errors on the presence probe, exports
    /// fine. This is the OLDER half of the real table.
    TooOldButExports(Vec<Key>),
    /// Too old to know `HasIdentity`, and exports nothing. Genuinely
    /// ambiguous.
    TooOldAndEmpty,
    /// The request never left the browser (dead socket).
    TransportFailure(&'static str),
}

impl PredecessorState {
    /// The reply to `GhostkeyRequest::HasIdentity`.
    fn presence_reply(&self) -> Result<GhostkeyResponse, DelegateCallError> {
        match self {
            Self::HoldsAndExports(keys) => Ok(GhostkeyResponse::IdentityPresence {
                usable: keys.len(),
                unusable: 0,
            }),
            Self::HoldsThenSilent | Self::HoldsThenExportsNothing => {
                Ok(GhostkeyResponse::IdentityPresence {
                    usable: 1,
                    unusable: 0,
                })
            }
            Self::RegisteredButEmpty => Ok(GhostkeyResponse::IdentityPresence {
                usable: 0,
                unusable: 0,
            }),
            Self::NotRegistered => Err(DelegateCallError::NotRegistered),
            Self::Silent => Err(DelegateCallError::TimedOut),
            Self::AnswersWithError(m) => Err(DelegateCallError::Failed((*m).to_string())),
            Self::TooOldButExports(_) | Self::TooOldAndEmpty => Ok(GhostkeyResponse::Error {
                message: "Unsupported request variant for this delegate version".into(),
            }),
            Self::TransportFailure(m) => Err(DelegateCallError::Transport((*m).to_string())),
        }
    }

    /// The reply to `GhostkeyRequest::ExportAllGhostKeys`.
    fn export_reply(&self) -> Result<GhostkeyResponse, DelegateCallError> {
        match self {
            Self::HoldsAndExports(keys) | Self::TooOldButExports(keys) => {
                Ok(GhostkeyResponse::ExportAllResult {
                    keys: keys.iter().map(Key::exported).collect(),
                })
            }
            Self::HoldsThenExportsNothing | Self::TooOldAndEmpty | Self::RegisteredButEmpty => {
                Ok(GhostkeyResponse::ExportAllResult { keys: Vec::new() })
            }
            Self::HoldsThenSilent | Self::Silent => Err(DelegateCallError::TimedOut),
            Self::NotRegistered => Err(DelegateCallError::NotRegistered),
            Self::AnswersWithError(m) => Err(DelegateCallError::Failed((*m).to_string())),
            Self::TransportFailure(m) => Err(DelegateCallError::Transport((*m).to_string())),
        }
    }
}

/// One predecessor in a scenario: a real registry row plus what it does.
#[derive(Debug, Clone)]
struct Predecessor {
    entry: LegacyEntry,
    /// Position in `legacy_delegates.toml`, oldest first. The crate needs a
    /// `generation`; the registry has none, so this is the only ordering
    /// available -- see `the_registry_has_no_generation_field`.
    generation: u32,
    state: PredecessorState,
}

/// Build a scenario from states, assigning each the identity of the real
/// registry row at the same position (oldest first).
fn predecessors(states: Vec<PredecessorState>) -> Vec<Predecessor> {
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

fn cert_key(fp: &str) -> Vec<u8> {
    format!("gk:cert:{fp}").into_bytes()
}
fn sk_key(fp: &str) -> Vec<u8> {
    format!("gk:sk:{fp}").into_bytes()
}
fn label_key(fp: &str) -> Vec<u8> {
    format!("gk:label:{fp}").into_bytes()
}
const INDEX_KEY: &[u8] = b"gk:index";

/// A model of the successor delegate's secret store, laid out exactly as
/// `delegates/ghostkey-delegate/src/handlers.rs` lays it out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Namespace {
    secrets: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Namespace {
    /// Seed the store with keys the current delegate already holds.
    fn with_keys(keys: &[Key]) -> Self {
        let mut ns = Self::default();
        for k in keys {
            ns.apply_import(k);
        }
        ns
    }

    /// A successor holding a key whose certificate survived but whose signing
    /// key did not -- the half-broken state `migration.rs` re-imports to heal.
    fn with_cert_only(fp: &str) -> Self {
        let mut ns = Self::default();
        ns.secrets.insert(cert_key(fp), b"CERT".to_vec());
        ns.set_index(&[fp.to_string()]);
        ns
    }

    fn index(&self) -> Vec<String> {
        self.secrets
            .get(INDEX_KEY)
            .and_then(|b| ghostkey_common::from_cbor::<Vec<String>>(b).ok())
            .unwrap_or_default()
    }

    fn set_index(&mut self, fps: &[String]) {
        self.secrets.insert(
            INDEX_KEY.to_vec(),
            ghostkey_common::to_cbor(&fps.to_vec()).expect("cbor"),
        );
    }

    /// The writes `handle_import` performs on a successful import
    /// (`handlers.rs::handle_import`): certificate, signing key, label, index.
    fn apply_import(&mut self, k: &Key) {
        self.secrets
            .insert(cert_key(k.fp), k.cert.as_bytes().to_vec());
        self.secrets.insert(sk_key(k.fp), k.sk.as_bytes().to_vec());
        if let Some(label) = k.label {
            self.secrets
                .insert(label_key(k.fp), label.as_bytes().to_vec());
        }
        let mut index = self.index();
        if !index.contains(&k.fp.to_string()) {
            index.push(k.fp.to_string());
        }
        self.set_index(&index);
    }

    /// What `ListGhostKeys` would report: the index, which is what the user
    /// actually sees in the vault.
    fn visible(&self) -> BTreeSet<String> {
        self.index().into_iter().collect()
    }

    /// Fingerprints with BOTH halves present, whatever the index says. A key
    /// here but not in `visible()` is stored and unreachable.
    fn complete_pairs(&self) -> BTreeSet<String> {
        self.secrets
            .keys()
            .filter_map(|k| {
                let s = String::from_utf8(k.clone()).ok()?;
                let fp = s.strip_prefix("gk:cert:")?.to_string();
                self.secrets.contains_key(&sk_key(&fp)).then_some(fp)
            })
            .collect()
    }
}

impl SecretStore for Namespace {
    fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.secrets
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.secrets.get(key).cloned()
    }
    fn has_secret(&self, key: &[u8]) -> bool {
        self.secrets.contains_key(key)
    }
    fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.secrets.insert(key.to_vec(), value.to_vec());
        true
    }
}

// ---------------------------------------------------------------------------
// Side A -- the shipped ghostkeys sweep
// ---------------------------------------------------------------------------

/// The bucket one predecessor landed in, named by the field the SHIPPED
/// `record_probe` incremented. Deriving it from the real function's effect
/// (rather than restating its match) is what keeps this an oracle: change
/// `record_probe` and this moves with it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GkBucket {
    /// Answered "I hold nothing"; `sweep_step` said Skip, so no export was even
    /// attempted and no counter moved.
    SkippedEmpty,
    /// Exported at least one key. `record_probe` increments nothing.
    Exported(usize),
    /// A counter moved; this is its field name.
    Counted(&'static str),
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
struct GkResult {
    per_predecessor: Vec<GkBucket>,
    outcome: MigrationOutcome,
    store: Namespace,
}

/// One pass of the ghostkeys sweep over `preds`.
///
/// The decisions are the shipped functions; only the loop wiring is
/// re-expressed here, because `run_pass` is wasm-only. The order below is
/// pinned against `migration.rs` by `the_harness_mirrors_the_shipped_sweep`.
fn run_ghostkeys_sweep(preds: &[Predecessor], mut store: Namespace) -> GkResult {
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
                fp: Box::leak(exported_key.fingerprint.clone().into_boxed_str()),
                cert: Box::leak(exported_key.certificate_pem.clone().into_boxed_str()),
                sk: Box::leak(exported_key.signing_key_pem.clone().into_boxed_str()),
                label: exported_key
                    .label
                    .clone()
                    .map(|l| &*Box::leak(l.into_boxed_str())),
            };
            store.apply_import(&k);
            held.insert(k.fp.to_string());
            if !already_held {
                outcome.record_import(true);
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
// Side B -- freenet-migrate 0.4.0
// ---------------------------------------------------------------------------

/// The transport error a ghostkeys adopter's adapter would surface.
#[derive(Debug, PartialEq, Eq)]
struct IoError(String);

/// The `PredecessorSecretsIo` a ghostkeys adopter would write.
///
/// It is deliberately the most charitable adapter available: it uses
/// `HasIdentity` as the "cheap no-op" preflight the crate asks for, treats any
/// *reply* as proof the predecessor executed, and dumps the full secret
/// namespace (certificate, signing key, label AND the `gk:index` list) so the
/// crate's raw-pair import has everything it could need.
struct GhostkeysIo<'a> {
    preds: &'a [Predecessor],
    probed: Vec<[u8; 32]>,
    fetched: Vec<[u8; 32]>,
}

impl<'a> GhostkeysIo<'a> {
    fn new(preds: &'a [Predecessor]) -> Self {
        Self {
            preds,
            probed: Vec::new(),
            fetched: Vec::new(),
        }
    }

    fn state_of(&self, key: &DelegateKey08) -> &PredecessorState {
        let bytes: [u8; 32] = key.bytes().try_into().expect("32-byte delegate key");
        &self
            .preds
            .iter()
            .find(|p| p.entry.delegate_key == bytes)
            .expect("probe for a predecessor not in the fixture")
            .state
    }
}

/// The documented mapping from a ghostkeys presence reply to the crate's
/// tri-state preflight. See the PR body's verdict table.
fn probe_executable_from(
    reply: Result<GhostkeyResponse, DelegateCallError>,
) -> Result<bool, IoError> {
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
        // Never left the browser.
        Err(DelegateCallError::Transport(m)) => Err(IoError(format!("transport: {m}"))),
    }
}

/// The documented mapping from a ghostkeys export reply to `fetch_secrets`.
fn fetch_secrets_from(
    reply: Result<GhostkeyResponse, DelegateCallError>,
) -> Result<Vec<SecretPair>, IoError> {
    match reply {
        Ok(GhostkeyResponse::ExportAllResult { keys }) => {
            let mut pairs: Vec<SecretPair> = Vec::new();
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
            Ok(pairs)
        }
        Ok(other) => Err(IoError(format!(
            "unexpected reply: {}",
            crate::api::delegate::response_kind(&other)
        ))),
        Err(e) => Err(IoError(e.to_string())),
    }
}

impl PredecessorSecretsIo for GhostkeysIo<'_> {
    type Error = IoError;

    async fn probe_executable(&mut self, predecessor: &DelegateKey08) -> Result<bool, IoError> {
        self.probed
            .push(predecessor.bytes().try_into().expect("32 bytes"));
        probe_executable_from(self.state_of(predecessor).presence_reply())
    }

    async fn fetch_secrets(
        &mut self,
        predecessor: &DelegateKey08,
    ) -> Result<Vec<SecretPair>, IoError> {
        self.fetched
            .push(predecessor.bytes().try_into().expect("32 bytes"));
        fetch_secrets_from(self.state_of(predecessor).export_reply())
    }
}

fn lineage(preds: &[Predecessor]) -> Vec<DelegateLineageEntry> {
    preds
        .iter()
        .map(|p| DelegateLineageEntry {
            generation: p.generation,
            code_hash: p.entry.code_hash,
            delegate_key: p.entry.delegate_key,
            irregular_key: false,
            note: "ghostkeys legacy_delegates.toml entry",
        })
        .collect()
}

#[derive(Debug)]
struct CrateResult {
    classifications: Vec<PredecessorMigration>,
    store: Namespace,
    probed: usize,
    fetched: usize,
}

fn run_crate_migration(
    preds: &[Predecessor],
    store: Namespace,
    policy: SecretSelectionPolicy,
) -> CrateResult {
    let mut store = store;
    let mut io = GhostkeysIo::new(preds);
    let entries = lineage(preds);
    let report = futures::executor::block_on(migrate_delegate_secrets(
        &mut store,
        &mut io,
        &entries,
        MigrationAuthorization::app_author_ack(),
        policy,
    ));
    CrateResult {
        classifications: report.predecessors,
        store,
        probed: io.probed.len(),
        fetched: io.fetched.len(),
    }
}

fn union() -> SecretSelectionPolicy {
    SecretSelectionPolicy::UnionAllGenerations(
        UnionAck::i_understand_union_resurrects_deleted_by_absence_secrets(),
    )
}

/// The classification variants, as bare names, in the crate's processing
/// (newest-first) order.
fn crate_names(r: &CrateResult) -> Vec<&'static str> {
    r.classifications
        .iter()
        .map(|c| match c {
            PredecessorMigration::Imported { .. } => "Imported",
            PredecessorMigration::NoData { .. } => "NoData",
            PredecessorMigration::AlreadyMigrated { .. } => "AlreadyMigrated",
            PredecessorMigration::Unresponsive { .. } => "Unresponsive",
            PredecessorMigration::Incomplete { .. } => "Incomplete",
            PredecessorMigration::Superseded { .. } => "Superseded",
        })
        .collect()
}

/// ghostkeys' per-predecessor buckets as bare names, in ITS processing
/// (oldest-first) order.
fn gk_names(r: &GkResult) -> Vec<String> {
    r.per_predecessor
        .iter()
        .map(|b| match b {
            GkBucket::SkippedEmpty => "SkippedEmpty".to_string(),
            GkBucket::Exported(n) => format!("Exported({n})"),
            GkBucket::Counted(name) => (*name).to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The agreement table
// ---------------------------------------------------------------------------

/// Whether the two implementations reach the same observable outcome for a
/// scenario, and if not, the name of the divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Agreement {
    /// Same secrets end up visible in the successor, same story per
    /// predecessor.
    Agree,
    /// Named divergence -- the finding, not a bug in the test. Never "fix" one
    /// of these by editing a fixture.
    Diverge(&'static str),
}

/// Every scenario, with its declared agreement. Adding a scenario without a row
/// here fails `every_scenario_has_a_declared_agreement`.
const SCENARIOS: &[(&str, Agreement)] = &[
    ("predecessor_holds_keys_and_exports_them", Agreement::Agree),
    ("predecessor_registered_but_holds_nothing", Agreement::Agree),
    (
        "predecessor_not_registered",
        Agreement::Diverge("not-registered and silence collapse into one Unresponsive"),
    ),
    (
        "predecessor_times_out",
        Agreement::Diverge("NewestSnapshotWins halts the whole walk on the first silence"),
    ),
    (
        "predecessor_answers_with_an_error",
        Agreement::Diverge("an answered failure is reported as Unresponsive, the silence bucket"),
    ),
    (
        "multiple_generations_newest_already_has_the_data",
        Agreement::Diverge("NewestSnapshotWins strands keys unique to an older generation"),
    ),
    (
        "rerun_is_idempotent",
        Agreement::Diverge("the crate seals a predecessor with a marker; the sweep re-probes"),
    ),
    (
        "successor_holds_a_half_broken_key",
        Agreement::Diverge("never-clobber leaves a cert-only key unhealed"),
    ),
    (
        "imported_keys_are_visible_to_the_user",
        Agreement::Diverge("never-clobber skips gk:index, so imported keys stay invisible"),
    ),
];

fn declared(name: &str) -> Agreement {
    SCENARIOS
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("scenario `{name}` has no row in SCENARIOS"))
        .1
}

// ===========================================================================
// Scenarios
// ===========================================================================

/// **Expected before running:** both sides import both keys, both make them
/// visible, and both classify the predecessor as a successful data-bearing
/// import. This is the case the convergent-design claim rests on, and it holds.
#[test]
fn predecessor_holds_keys_and_exports_them() {
    let keys = vec![key("fpA", Some("work")), key("fpB", None)];
    let preds = predecessors(vec![PredecessorState::HoldsAndExports(keys.clone())]);

    let gk = run_ghostkeys_sweep(&preds, Namespace::default());
    assert_eq!(gk_names(&gk), vec!["Exported(2)"]);
    assert_eq!(gk.outcome.recovered, 2);
    assert_eq!(
        gk.store.visible(),
        BTreeSet::from(["fpA".to_string(), "fpB".to_string()])
    );

    let cr = run_crate_migration(
        &preds,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(crate_names(&cr), vec!["Imported"]);
    assert_eq!(
        cr.store.visible(),
        BTreeSet::from(["fpA".to_string(), "fpB".to_string()])
    );

    assert_eq!(gk.store.visible(), cr.store.visible());
    assert_eq!(gk.store.complete_pairs(), cr.store.complete_pairs());
    assert_eq!(
        declared("predecessor_holds_keys_and_exports_them"),
        Agreement::Agree
    );
}

/// **Expected before running:** nothing is imported either way, and neither
/// side raises anything. ghostkeys skips before asking for keys (so no
/// private-key dialog fires); the crate probes, fetches an empty set and
/// records `NoData`. Different mechanics, same observable outcome.
#[test]
fn predecessor_registered_but_holds_nothing() {
    let preds = predecessors(vec![PredecessorState::RegisteredButEmpty]);

    let gk = run_ghostkeys_sweep(&preds, Namespace::default());
    assert_eq!(gk_names(&gk), vec!["SkippedEmpty"]);
    assert_eq!(gk.outcome.recovered, 0);
    assert!(gk.outcome.is_conclusive());

    let cr = run_crate_migration(
        &preds,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(crate_names(&cr), vec!["NoData"]);

    assert_eq!(gk.store.visible(), cr.store.visible());
    assert!(gk.store.visible().is_empty());
    assert_eq!(
        declared("predecessor_registered_but_holds_nothing"),
        Agreement::Agree
    );
}

/// **Expected before running:** ghostkeys files this under `not_registered`, a
/// bucket it keeps separate from silence precisely because nothing ever
/// re-registers legacy code. The crate has no such bucket -- `probe_executable`
/// is a bool, so "the node does not have it" and "it did not answer in time"
/// both land in `Unresponsive`.
///
/// **Divergence:** classification only, no key loss in this scenario.
#[test]
fn predecessor_not_registered() {
    let preds = predecessors(vec![PredecessorState::NotRegistered]);

    let gk = run_ghostkeys_sweep(&preds, Namespace::default());
    assert_eq!(gk_names(&gk), vec!["not_registered"]);
    assert_eq!(gk.outcome.not_registered, 1);
    assert_eq!(gk.outcome.undetermined, 0, "kept apart from silence");

    let cr = run_crate_migration(
        &preds,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(crate_names(&cr), vec!["Unresponsive"]);

    // Same silent scenario, different ghostkeys bucket, SAME crate bucket:
    // that is the collapse.
    let silent = predecessors(vec![PredecessorState::Silent]);
    let gk_silent = run_ghostkeys_sweep(&silent, Namespace::default());
    let cr_silent = run_crate_migration(
        &silent,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_ne!(
        gk_names(&gk),
        gk_names(&gk_silent),
        "ghostkeys distinguishes not-registered from silence"
    );
    assert_eq!(
        crate_names(&cr),
        crate_names(&cr_silent),
        "the crate does not: both are Unresponsive"
    );

    assert_eq!(
        declared("predecessor_not_registered"),
        Agreement::Diverge("not-registered and silence collapse into one Unresponsive")
    );
}

/// **Expected before running:** this is the important one. Silence is the
/// ORDINARY case -- `migration.rs`'s header records nine legacy entries
/// producing nine timeouts on a real node -- so the sweep must walk straight
/// past it. The crate's default policy treats an unresponsive predecessor as a
/// reason to STOP: `unresponsive_terminates()` is true under
/// `NewestSnapshotWins`, and every older predecessor is then `Superseded`
/// without ever being probed.
///
/// **Divergence: key loss under the crate's default policy.** With one silent
/// newest predecessor in front of a data-bearing older one, ghostkeys recovers
/// the keys and the crate recovers nothing. `UnionAllGenerations` does not
/// terminate, and recovers them.
#[test]
fn predecessor_times_out() {
    let keys = vec![key("fpOld", None)];
    let preds = predecessors(vec![
        PredecessorState::HoldsAndExports(keys.clone()), // generation 0, older
        PredecessorState::Silent,                        // generation 1, newer
    ]);

    let gk = run_ghostkeys_sweep(&preds, Namespace::default());
    assert_eq!(gk_names(&gk), vec!["Exported(1)", "undetermined"]);
    assert_eq!(gk.store.visible(), BTreeSet::from(["fpOld".to_string()]));
    assert!(
        !gk.outcome.needs_user_attention(),
        "silence is the normal case and must stay quiet"
    );

    let cr = run_crate_migration(
        &preds,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(
        crate_names(&cr),
        vec!["Unresponsive", "Superseded"],
        "newest-first: the silent generation halts the walk"
    );
    assert_eq!(
        cr.probed, 1,
        "the older, data-bearing generation is never probed"
    );
    assert!(
        cr.store.visible().is_empty(),
        "the crate's default policy recovers nothing here"
    );

    // Union does not terminate on Unresponsive, and gets the keys.
    let cr_union = run_crate_migration(&preds, Namespace::default(), union());
    assert_eq!(crate_names(&cr_union), vec!["Unresponsive", "Imported"]);
    assert_eq!(cr_union.store.visible(), gk.store.visible());

    assert_ne!(gk.store.visible(), cr.store.visible());
    assert_eq!(
        declared("predecessor_times_out"),
        Agreement::Diverge("NewestSnapshotWins halts the whole walk on the first silence")
    );
}

/// **Expected before running:** ghostkeys files a delegate-level failure under
/// `answered_with_error` and TELLS THE USER -- that bucket exists so the
/// crying-wolf fix for silence does not also mute positive evidence that
/// something is there and unreadable. The crate has one bucket for both, so an
/// adopter reading `any_unresponsive()` cannot tell an error reply from the
/// eleven routine timeouts it will see on every open.
///
/// **Divergence:** the user-facing signal is lost, not the keys.
#[test]
fn predecessor_answers_with_an_error() {
    let preds = predecessors(vec![PredecessorState::AnswersWithError(
        "missing secret gk:sk:abc",
    )]);

    let gk = run_ghostkeys_sweep(&preds, Namespace::default());
    assert_eq!(gk_names(&gk), vec!["answered_with_error"]);
    assert!(
        gk.outcome.needs_user_attention(),
        "an answered failure is positive evidence and reaches the user"
    );

    let cr = run_crate_migration(
        &preds,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(crate_names(&cr), vec!["Unresponsive"]);

    // The crate does carry the error string, but in the same variant silence
    // uses -- so `any_unresponsive()` cannot separate them.
    let silent = predecessors(vec![PredecessorState::Silent]);
    let cr_silent = run_crate_migration(
        &silent,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(crate_names(&cr), crate_names(&cr_silent));

    let gk_silent = run_ghostkeys_sweep(&silent, Namespace::default());
    assert!(
        !gk_silent.outcome.needs_user_attention(),
        "silence must stay quiet -- which is why the two buckets cannot merge"
    );

    assert_eq!(
        declared("predecessor_answers_with_an_error"),
        Agreement::Diverge("an answered failure is reported as Unresponsive, the silence bucket")
    );
}

/// **Expected before running:** a user with one key created under generation 0
/// and another under generation 2 has both recovered by ghostkeys, which sweeps
/// every entry. Under `NewestSnapshotWins` the crate stops at generation 2 --
/// the newest predecessor that yielded data is authoritative -- so `fpOld` is
/// `Superseded` and lost. That is the policy working as designed
/// (delete-by-absence preservation), and it is the wrong default for ghostkeys,
/// whose predecessors are not snapshots of one evolving state but separate
/// stores of independently-created purchased keys.
///
/// **Divergence: key loss.** `UnionAllGenerations` matches ghostkeys.
#[test]
fn multiple_generations_newest_already_has_the_data() {
    let preds = predecessors(vec![
        PredecessorState::HoldsAndExports(vec![key("fpOld", None)]), // gen 0
        PredecessorState::RegisteredButEmpty,                        // gen 1
        PredecessorState::HoldsAndExports(vec![key("fpNew", None)]), // gen 2
    ]);

    let gk = run_ghostkeys_sweep(&preds, Namespace::default());
    assert_eq!(
        gk_names(&gk),
        vec!["Exported(1)", "SkippedEmpty", "Exported(1)"]
    );
    assert_eq!(
        gk.store.visible(),
        BTreeSet::from(["fpOld".to_string(), "fpNew".to_string()]),
        "the sweep recovers from every generation"
    );

    let cr = run_crate_migration(
        &preds,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(
        crate_names(&cr),
        vec!["Imported", "Superseded", "Superseded"],
        "newest-first, stopping at the first data-bearing generation"
    );
    assert_eq!(
        cr.store.visible(),
        BTreeSet::from(["fpNew".to_string()]),
        "fpOld is stranded"
    );

    // Union recovers the BYTES of both generations -- and still cannot make
    // them both visible. `gk:index` is one slot, the newest generation writes
    // it first, and never-clobber skips every later one. So no crate policy
    // reproduces the sweep's result here; this was not predicted before the
    // run, and it is the finding that survives switching policy.
    let cr_union = run_crate_migration(&preds, Namespace::default(), union());
    assert_eq!(
        crate_names(&cr_union),
        vec!["Imported", "NoData", "Imported"]
    );
    assert_eq!(
        cr_union.store.complete_pairs(),
        BTreeSet::from(["fpOld".to_string(), "fpNew".to_string()]),
        "Union does fix the SELECTION divergence"
    );
    assert_eq!(
        cr_union.store.visible(),
        BTreeSet::from(["fpNew".to_string()]),
        "but the older generation's index write is clobber-skipped, so fpOld stays invisible"
    );
    assert_ne!(cr_union.store.visible(), gk.store.visible());

    assert_ne!(gk.store.visible(), cr.store.visible());
    assert_eq!(
        declared("multiple_generations_newest_already_has_the_data"),
        Agreement::Diverge("NewestSnapshotWins strands keys unique to an older generation")
    );
}

/// **Expected before running:** ghostkeys' second pass re-probes everything and
/// re-imports, by design -- its module header argues at length that no
/// available signal justifies a "migration done" flag, because an empty export
/// is not proof of absence (`ExportAllGhostKeys` silently skips keys the caller
/// lacks `Export` scope on). The crate writes a `pred-done` marker, including
/// for a predecessor that exported NOTHING, and short-circuits forever after.
///
/// **Divergence: the sealed-empty case.** A predecessor that answered empty
/// because this vault had no `Export` scope at the time is marked done and
/// never asked again, even once the scope is granted. Demonstrated below: the
/// predecessor gains data between the two passes, ghostkeys recovers it, the
/// crate does not.
#[test]
fn rerun_is_idempotent() {
    let first = predecessors(vec![PredecessorState::TooOldAndEmpty]);

    // Pass 1: nothing to take, both sides agree.
    let gk1 = run_ghostkeys_sweep(&first, Namespace::default());
    assert_eq!(gk_names(&gk1), vec!["unsettled_and_empty"]);
    let cr1 = run_crate_migration(
        &first,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(crate_names(&cr1), vec!["NoData"]);
    assert!(gk1.store.visible().is_empty() && cr1.store.visible().is_empty());

    // Pass 2 over the SAME store: the predecessor now hands over a key (the
    // user granted Export scope, or a missed dialog was answered).
    let second = predecessors(vec![PredecessorState::TooOldButExports(vec![key(
        "fpLate", None,
    )])]);

    let gk2 = run_ghostkeys_sweep(&second, gk1.store.clone());
    assert_eq!(gk_names(&gk2), vec!["Exported(1)"]);
    assert_eq!(
        gk2.store.visible(),
        BTreeSet::from(["fpLate".to_string()]),
        "re-sweeping every startup is what recovers this"
    );

    let cr2 = run_crate_migration(
        &second,
        cr1.store.clone(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(
        crate_names(&cr2),
        vec!["AlreadyMigrated"],
        "the empty marker written in pass 1 seals the predecessor"
    );
    assert_eq!(cr2.probed, 0, "not even probed on the re-run");
    assert!(
        cr2.store.visible().is_empty(),
        "fpLate is never recovered by the crate"
    );

    // A true re-run with no change IS a no-op both ways -- the crate does
    // nothing, and ghostkeys re-imports the same bytes over themselves, which
    // leaves the store identical and reports no new recovery.
    let gk_rerun = run_ghostkeys_sweep(&second, gk2.store.clone());
    assert_eq!(gk_rerun.outcome.recovered, 0, "no double-counting");
    assert_eq!(gk_rerun.store, gk2.store, "re-import is idempotent");

    assert_eq!(
        declared("rerun_is_idempotent"),
        Agreement::Diverge("the crate seals a predecessor with a marker; the sweep re-probes")
    );
}

/// **Expected before running:** the successor lists `fpA` because its
/// certificate loaded, but its signing key is gone -- the key looks present and
/// cannot sign. `migration.rs` re-imports unconditionally to overwrite both
/// halves and heal it. The crate's import is never-clobber, so it writes the
/// missing signing key (absent) but SKIPS the certificate (present) -- which
/// happens to heal this particular shape.
///
/// **Divergence:** the crate leaves the stale certificate in place. Here the
/// certificate is intact so the outcome is benign, but the inverse shape (a
/// stale or corrupt certificate with a good signing key) is not healed at all,
/// which is checked below.
#[test]
fn successor_holds_a_half_broken_key() {
    let good = key("fpA", None);
    let preds = predecessors(vec![PredecessorState::HoldsAndExports(vec![good.clone()])]);

    let gk = run_ghostkeys_sweep(&preds, Namespace::with_cert_only("fpA"));
    assert_eq!(
        gk.store.secrets.get(&cert_key("fpA")).map(|v| v.as_slice()),
        Some(good.cert.as_bytes()),
        "the sweep overwrites both halves"
    );
    assert_eq!(
        gk.store.secrets.get(&sk_key("fpA")).map(|v| v.as_slice()),
        Some(good.sk.as_bytes())
    );
    assert_eq!(
        gk.outcome.recovered, 0,
        "already listed, so healed without announcing a recovery"
    );

    let cr = run_crate_migration(
        &preds,
        Namespace::with_cert_only("fpA"),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(
        cr.store.secrets.get(&cert_key("fpA")).map(|v| v.as_slice()),
        Some(b"CERT".as_slice()),
        "never-clobber keeps the successor's stale certificate"
    );
    assert_eq!(
        cr.store.secrets.get(&sk_key("fpA")).map(|v| v.as_slice()),
        Some(good.sk.as_bytes()),
        "the missing half IS written"
    );

    assert_ne!(gk.store.secrets, cr.store.secrets);
    assert_eq!(
        declared("successor_holds_a_half_broken_key"),
        Agreement::Diverge("never-clobber leaves a cert-only key unhealed")
    );
}

/// **Expected before running:** the severe one. `gk:index` is a single CBOR
/// secret holding the fingerprint list, and `ListGhostKeys` reads it -- so a
/// key whose `gk:cert:`/`gk:sk:` pair is stored but whose fingerprint is not in
/// the index does not exist as far as the user is concerned.
///
/// ghostkeys imports through `ImportGhostKey`, whose handler appends to the
/// index. The crate writes raw pairs never-clobber, and the successor's index
/// already exists (the user made a key on the new version before the sweep
/// ran), so the predecessor's index is SKIPPED. The recovered keys are in the
/// store and invisible.
///
/// **Divergence: silent, total loss of the recovered keys from the user's
/// point of view.** This is not a policy choice; it is the raw-pair transport
/// meeting an app whose store has a derived index.
#[test]
fn imported_keys_are_visible_to_the_user() {
    let own = key("fpMine", None);
    let recovered = key("fpOld", None);
    let preds = predecessors(vec![PredecessorState::HoldsAndExports(vec![
        recovered.clone()
    ])]);

    let gk = run_ghostkeys_sweep(&preds, Namespace::with_keys(std::slice::from_ref(&own)));
    assert_eq!(
        gk.store.visible(),
        BTreeSet::from(["fpMine".to_string(), "fpOld".to_string()]),
        "the import handler appends to the index"
    );

    let cr = run_crate_migration(
        &preds,
        Namespace::with_keys(std::slice::from_ref(&own)),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(
        cr.store.complete_pairs(),
        BTreeSet::from(["fpMine".to_string(), "fpOld".to_string()]),
        "both halves of fpOld ARE written"
    );
    assert_eq!(
        cr.store.visible(),
        BTreeSet::from(["fpMine".to_string()]),
        "but gk:index was skipped by never-clobber, so fpOld is invisible"
    );

    assert_ne!(gk.store.visible(), cr.store.visible());
    assert_eq!(
        declared("imported_keys_are_visible_to_the_user"),
        Agreement::Diverge("never-clobber skips gk:index, so imported keys stay invisible")
    );
}

// ===========================================================================
// Meta-tests: the oracle, the table, and the adoption costs
// ===========================================================================

/// Every `#[test]` in this module must have a row in [`SCENARIOS`], so a new
/// fixture cannot be added without declaring whether the two implementations
/// agree on it.
#[test]
fn every_scenario_has_a_declared_agreement() {
    let src = include_str!("migration_differential.rs");
    let marker = "// ===========================================================================\n// Scenarios";
    assert!(src.contains(marker), "the scenario-section marker moved");
    let scenarios_section = src
        .split(marker)
        .nth(1)
        .expect("marker asserted above")
        .split("// Meta-tests")
        .next()
        .expect("meta-test marker");

    let mut found = Vec::new();
    for line in scenarios_section.lines() {
        if let Some(name) = line.trim().strip_prefix("fn ") {
            found.push(name.trim_end_matches("() {").to_string());
        }
    }
    assert!(!found.is_empty(), "scrape found no scenario tests");
    for name in &found {
        assert!(
            SCENARIOS.iter().any(|(n, _)| n == name),
            "scenario `{name}` has no row in SCENARIOS"
        );
    }
    for (name, _) in SCENARIOS {
        assert!(
            found.contains(&name.to_string()),
            "SCENARIOS lists `{name}`, which is not a scenario test"
        );
    }
}

/// The oracle's integrity check.
///
/// [`run_ghostkeys_sweep`] re-expresses `run_pass`'s loop wiring because that
/// function is wasm-only. This pins the two together: the shipped sweep must
/// still call the same decisions in the same order, and must still walk the
/// table without an early exit. If `run_pass` is restructured, this fails and
/// the harness has to be brought back into line rather than silently becoming
/// a test of something that is no longer shipped.
#[test]
fn the_harness_mirrors_the_shipped_sweep() {
    let src = include_str!("migration.rs");
    const TEST_MODULE_MARKER: &str = "#[cfg(test)]\nmod tests {";
    assert!(
        src.contains(TEST_MODULE_MARKER),
        "the test-module marker moved; this scrape would otherwise match string literals"
    );
    let code = src.split(TEST_MODULE_MARKER).next().unwrap();

    // The call sequence, in order. `find` from a moving offset, so a
    // reordering fails rather than passing on mere presence.
    let mut at = 0usize;
    for needle in [
        "let presence = presence_probe(&legacy_key).await;",
        "match super::sweep_step(&presence)",
        "GhostkeyRequest::ExportAllGhostKeys",
        "outcome.record_probe(&verdict, had_presence);",
        "GhostkeyRequest::ImportGhostKey",
        "outcome.record_import(true);",
    ] {
        let found = code[at..].find(needle).unwrap_or_else(|| {
            panic!("the shipped sweep no longer contains `{needle}` in the expected order")
        });
        at += found + needle.len();
    }

    // The sweep must keep walking the whole table. Every arm that gives up on
    // one entry uses `continue`, never `break`/`return`, so silence early in
    // the table cannot strand everything after it -- the exact property the
    // crate's NewestSnapshotWins policy does NOT have.
    let loop_at = code
        .find("for (delegate_key_bytes, code_hash_bytes) in LEGACY_DELEGATES")
        .expect("the sweep loop");
    let body = &code[loop_at..];
    let body = &body[..body
        .find("\n        }\n")
        .map(|i| i + 10)
        .unwrap_or(body.len())];
    assert!(
        !body.contains("break"),
        "the sweep must not stop early; a `break` in the loop would strand every later entry"
    );
}

/// Adoption cost, recorded as a test so it cannot rot: `freenet-migrate` 0.4.0
/// requires `freenet-stdlib` 0.8, ghostkeys is on 0.6, and the two are
/// semver-incompatible. They coexist here only because the crate is a
/// dev-dependency and the differential converts between them by raw key bytes.
/// A real adoption has to reconcile the versions, and bumping the stdlib the
/// DELEGATE builds against re-keys the delegate -- i.e. adopting the migration
/// crate would itself trigger a migration.
#[test]
fn the_crate_forces_a_second_freenet_stdlib_into_the_graph() {
    let entry = legacy_entries()[0];
    // ghostkeys' own stdlib (0.6)
    let gk_key = freenet_stdlib::prelude::DelegateKey::new(
        entry.delegate_key,
        freenet_stdlib::prelude::CodeHash::new(entry.code_hash),
    );
    // the crate's stdlib (0.8)
    let crate_key = DelegateKey08::new(entry.delegate_key, CodeHash08::new(entry.code_hash));
    assert_eq!(
        gk_key.bytes(),
        crate_key.bytes(),
        "the key bytes agree, so the differential's conversion is sound"
    );
    // Same bytes, different types: they cannot be compared without going
    // through bytes, which is the whole problem.
    assert_eq!(gk_key.encode(), crate_key.encode());
}

/// The registry the vault actually ships has no generation column, and the
/// crate's `DelegateLineageEntry` requires one. File order is the only
/// ordering available -- and it is not reliably chronological: two rows record
/// a local build and a CI build of the SAME delegate change (the
/// reproducibility gap documented in the file), so at least one pair of
/// "generations" is an invention of the adapter, not a fact about the lineage.
#[test]
fn the_registry_has_no_generation_field() {
    assert!(
        !LEGACY_DELEGATES_TOML.contains("generation"),
        "if a generation column has been added, this adapter's numbering is no longer a guess"
    );
    let entries = legacy_entries();
    assert_eq!(entries.len(), 12, "the real registry, as build.rs reads it");
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

/// `MigrationAuthorization` is a compile-time forcing function with an empty
/// runtime arm. Sound at this boundary (the caller is the app's own client
/// code), and the whole cost of it is one explicit call -- worth recording,
/// because it is the only *ergonomic* item on the adoption ledger that turns
/// out to be free.
#[test]
fn the_authorization_gate_costs_one_call() {
    let a = MigrationAuthorization::app_author_ack();
    assert_eq!(a, MigrationAuthorization::app_author_ack());
}
