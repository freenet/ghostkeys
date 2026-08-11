//! The `freenet-migrate` half of the differential (freenet-core#2776 §3).
//!
//! Replays the fixture inputs recorded by ghostkeys' shipped sweep
//! (`tests/migration-differential/observations.json`, written and re-verified
//! by `ui/src/migration_differential.rs`) through `migrate_delegate_secrets`,
//! and compares the observable outcome: which secrets end up in the successor
//! store, which of them the user can see, and how each predecessor is
//! classified.
//!
//! # Why this is a separate crate
//!
//! `freenet-migrate` 0.4.0 requires `freenet-stdlib` 0.8 and ghostkeys is on
//! 0.6. Both versions export `#[no_mangle] extern "C" __frnt_set_id`
//! unconditionally, so linking them into one binary fails with `duplicate
//! symbol`. `ghostkey-common` genuinely needs stdlib types, so no ghostkeys
//! crate can link the migration crate at all today. This crate therefore
//! depends on nothing from ghostkeys; the recorded observations are the seam.
//!
//! # The oracle
//!
//! Every expected ghostkeys value here was produced by the shipped sweep, not
//! by this crate. Nothing in this file computes what ghostkeys "should" have
//! done -- it reads what ghostkeys *did*.

use std::collections::{BTreeMap, BTreeSet};

use freenet_migrate::{
    migrate_delegate_secrets, DelegateLineageEntry, MigrationAuthorization,
    NoCrossEntryInvariantsAck, PredecessorMigration, PredecessorSecretsIo, SecretPair,
    SecretSelectionPolicy, SecretStore, SecretStoreIo, UnionAck, PRED_DONE_MARKER_KEY_PREFIX,
};
use freenet_stdlib::prelude::{CodeHash, DelegateKey};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// The recorded observations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
enum Agreement {
    /// Same secrets stored, same secrets visible.
    Agree,
    /// The stores agree; the crate cannot express ghostkeys' classification.
    DivergeClassification(String),
    /// Different secrets end up stored or visible. Key loss, or invisible keys.
    DivergeOutcome(String),
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedPredecessor {
    delegate_key: String,
    code_hash: String,
    generation: u32,
    probe: Result<bool, String>,
    fetch: Result<Vec<(String, String)>, String>,
    ghostkeys_bucket: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedScenario {
    name: String,
    #[allow(dead_code)]
    what_it_shows: String,
    agreement: Agreement,
    initial_store: Vec<(String, String)>,
    /// Secret keys the successor's storage refuses to write. `set_secret`
    /// returns false for exactly these, which is how the crate learns about a
    /// storage failure.
    failing_secret_keys: Vec<String>,
    predecessors: Vec<RecordedPredecessor>,
    #[allow(dead_code)]
    ghostkeys_store: Vec<(String, String)>,
    ghostkeys_visible: Vec<String>,
    #[allow(dead_code)]
    ghostkeys_indexed: Vec<String>,
    ghostkeys_complete_pairs: Vec<String>,
    #[allow(dead_code)]
    ghostkeys_recovered: usize,
    ghostkeys_failed_imports: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct Observations {
    #[allow(dead_code)]
    generated_by: String,
    scenarios: Vec<RecordedScenario>,
}

const OBSERVATIONS: &str = include_str!("../../tests/migration-differential/observations.json");

fn observations() -> Observations {
    serde_json::from_str(OBSERVATIONS).expect("the recorded observations must parse")
}

fn scenario(name: &str) -> RecordedScenario {
    observations()
        .scenarios
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no recorded scenario `{name}`"))
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

// ---------------------------------------------------------------------------
// The successor store, in the delegate's own secret layout
// ---------------------------------------------------------------------------

fn cert_key(fp: &str) -> Vec<u8> {
    format!("gk:cert:{fp}").into_bytes()
}
fn sk_key(fp: &str) -> Vec<u8> {
    format!("gk:sk:{fp}").into_bytes()
}
fn perm_key(fp: &str) -> Vec<u8> {
    format!("gk:perms:{fp}").into_bytes()
}
const INDEX_KEY: &[u8] = b"gk:index";

#[derive(Debug, Clone, Default)]
struct Namespace {
    secrets: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Secret keys this store refuses to write, from the recorded fixture.
    failing: BTreeSet<Vec<u8>>,
}

impl Namespace {
    fn from_recorded(scenario: &RecordedScenario) -> Self {
        Self {
            secrets: scenario
                .initial_store
                .iter()
                .map(|(k, v)| (unhex(k), unhex(v)))
                .collect(),
            failing: scenario
                .failing_secret_keys
                .iter()
                .map(|k| unhex(k))
                .collect(),
        }
    }

    /// Raw `gk:index` membership.
    ///
    /// Decoded without `ghostkey_common` (which this crate cannot link): the
    /// index is a CBOR array of text strings, so the bytes are read directly.
    fn indexed(&self) -> BTreeSet<String> {
        let Some(bytes) = self.secrets.get(INDEX_KEY) else {
            return BTreeSet::new();
        };
        decode_cbor_string_array(bytes)
            .unwrap_or_else(|| panic!("gk:index is not a CBOR string array: {bytes:?}"))
            .into_iter()
            .collect()
    }

    /// What `ListGhostKeys` actually reports: indexed AND carrying a permission
    /// grant, because `handle_list` skips every fingerprint the requestor lacks
    /// `ReadPublic` on (`handlers.rs:411`).
    ///
    /// Presence of `gk:perms:<fp>` is a sufficient proxy here: ghostkeys writes
    /// a full-scope grant on every import (so presence implies `ReadPublic`,
    /// which the ghostkeys side asserts by decoding the real blob), and the
    /// crate writes no grant at all, because permissions are not among the
    /// exported pairs and no adapter could supply them.
    fn visible(&self) -> BTreeSet<String> {
        self.indexed()
            .into_iter()
            .filter(|fp| self.secrets.contains_key(&perm_key(fp)))
            .collect()
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

    fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.secrets.get(key).map(Vec::as_slice)
    }

    /// The store minus this crate's own bookkeeping. ghostkeys has no
    /// equivalent of the `pred-done` / `pred-wip` markers, so comparing raw
    /// stores without excluding them would report a divergence on every
    /// scenario and drown the real ones.
    ///
    /// The namespace is taken from the crate's own exported prefix rather than
    /// hardcoded, so a future rename cannot silently turn markers into
    /// "differences".
    fn app_secrets(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let ns = marker_namespace();
        self.secrets
            .iter()
            .filter(|(k, _)| !k.starts_with(ns))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Minimal CBOR reader for the one shape `gk:index` uses: a definite-length
/// array (major type 4) of definite-length text strings (major type 3), both
/// with counts under 24 or in a one-byte follower. Returns `None` if the bytes
/// are anything else, so a silent misread cannot be mistaken for an empty
/// index.
fn decode_cbor_string_array(bytes: &[u8]) -> Option<Vec<String>> {
    fn head(bytes: &[u8], at: &mut usize, major: u8) -> Option<usize> {
        let b = *bytes.get(*at)?;
        *at += 1;
        if b >> 5 != major {
            return None;
        }
        match b & 0x1f {
            n if n < 24 => Some(n as usize),
            24 => {
                let n = *bytes.get(*at)?;
                *at += 1;
                Some(n as usize)
            }
            _ => None,
        }
    }

    let mut at = 0usize;
    let len = head(bytes, &mut at, 4)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let n = head(bytes, &mut at, 3)?;
        let s = bytes.get(at..at + n)?;
        at += n;
        out.push(String::from_utf8(s.to_vec()).ok()?);
    }
    (at == bytes.len()).then_some(out)
}

/// The reserved namespace every freenet-migrate marker key sits under, derived
/// from the crate's exported completion-marker prefix (`\0freenet-migrate/`).
fn marker_namespace() -> &'static [u8] {
    let prefix = PRED_DONE_MARKER_KEY_PREFIX;
    let slash = prefix
        .iter()
        .position(|b| *b == b'/')
        .expect("the marker prefix is namespaced");
    &prefix[..=slash]
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
        if self.failing.contains(key) {
            return false;
        }
        self.secrets.insert(key.to_vec(), value.to_vec());
        true
    }
}

// ---------------------------------------------------------------------------
// Replaying the recorded adapter results
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct IoError(String);

/// Replays exactly what ghostkeys' adapter returned for each predecessor. It
/// invents nothing: `probe` and `fetch` are read from the record.
struct RecordedIo {
    by_key: BTreeMap<[u8; 32], RecordedPredecessor>,
    probed: Vec<[u8; 32]>,
    fetched: Vec<[u8; 32]>,
}

impl RecordedIo {
    fn new(preds: &[RecordedPredecessor]) -> Self {
        Self {
            by_key: preds
                .iter()
                .map(|p| (unhex32(&p.delegate_key), p.clone()))
                .collect(),
            probed: Vec::new(),
            fetched: Vec::new(),
        }
    }

    fn recorded(&self, key: &DelegateKey) -> &RecordedPredecessor {
        let bytes: [u8; 32] = key.bytes().try_into().expect("32-byte delegate key");
        self.by_key
            .get(&bytes)
            .expect("probe for a predecessor not in the record")
    }
}

impl PredecessorSecretsIo for RecordedIo {
    type Error = IoError;

    async fn probe_executable(&mut self, predecessor: &DelegateKey) -> Result<bool, IoError> {
        self.probed
            .push(predecessor.bytes().try_into().expect("32 bytes"));
        self.recorded(predecessor).probe.clone().map_err(IoError)
    }

    async fn fetch_secrets(
        &mut self,
        predecessor: &DelegateKey,
    ) -> Result<Vec<SecretPair>, IoError> {
        self.fetched
            .push(predecessor.bytes().try_into().expect("32 bytes"));
        match self.recorded(predecessor).fetch.clone() {
            Ok(pairs) => Ok(pairs.iter().map(|(k, v)| (unhex(k), unhex(v))).collect()),
            Err(e) => Err(IoError(e)),
        }
    }
}

fn lineage(preds: &[RecordedPredecessor]) -> Vec<DelegateLineageEntry> {
    preds
        .iter()
        .map(|p| DelegateLineageEntry {
            generation: p.generation,
            code_hash: unhex32(&p.code_hash),
            delegate_key: unhex32(&p.delegate_key),
            irregular_key: false,
            note: "ghostkeys legacy_delegates.toml entry",
        })
        .collect()
}

struct CrateResult {
    classifications: Vec<String>,
    store: Namespace,
    probed: usize,
    fetched: usize,
}

fn run(scenario: &RecordedScenario, policy: SecretSelectionPolicy) -> CrateResult {
    run_over(
        &scenario.predecessors,
        Namespace::from_recorded(scenario),
        policy,
    )
}

fn run_over(
    preds: &[RecordedPredecessor],
    store: Namespace,
    policy: SecretSelectionPolicy,
) -> CrateResult {
    let mut store = store;
    let mut io = RecordedIo::new(preds);
    let entries = lineage(preds);
    // 0.5.0 port: `SecretStoreIo` is the raw-pair writer pinned byte-for-byte to
    // the pre-0.5.0 behaviour, so these tests keep measuring what PR #32
    // measured -- the 0.4.0 raw key/value copy. The seam writer the adoption
    // would actually use is measured separately in `mod seam` below.
    let mut writer = SecretStoreIo::new(
        &mut store,
        NoCrossEntryInvariantsAck::i_certify_these_secrets_have_no_cross_entry_invariants(),
    );
    let report = futures::executor::block_on(migrate_delegate_secrets(
        &mut writer,
        &mut io,
        &entries,
        MigrationAuthorization::app_author_ack(),
        policy,
    ));
    CrateResult {
        classifications: report
            .predecessors
            .iter()
            .map(|c| match c {
                PredecessorMigration::Imported { .. } => "Imported".to_string(),
                PredecessorMigration::NoData { .. } => "NoData".to_string(),
                PredecessorMigration::AlreadyMigrated { .. } => "AlreadyMigrated".to_string(),
                // The `error` field is part of the classification, not a
                // detail: `None` means the G1.8 preflight reported a clean
                // no-reply, `Some` means a round-trip errored. Folding them
                // together would let the preflight be deleted with every
                // assertion still passing.
                PredecessorMigration::Unresponsive { error: None, .. } => {
                    "Unresponsive(no-reply)".to_string()
                }
                PredecessorMigration::Unresponsive { error: Some(_), .. } => {
                    "Unresponsive(error)".to_string()
                }
                PredecessorMigration::Incomplete { .. } => "Incomplete".to_string(),
                PredecessorMigration::Superseded { .. } => "Superseded".to_string(),
                PredecessorMigration::WriterUnavailable { .. } => "WriterUnavailable".to_string(),
            })
            .collect(),
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

/// The shape a clean no-reply takes, for comparing not-registered against it.
fn r_silent_absent_shape() -> Vec<String> {
    vec!["Unresponsive(no-reply)".to_string()]
}

fn set(items: &[String]) -> BTreeSet<String> {
    items.iter().cloned().collect()
}

/// Assert the crate's store against ghostkeys' recorded store, and check that
/// the result matches the scenario's declared [`Agreement`]. `DivergeOutcome`
/// is not prose here: it asserts the stores really do differ, so a scenario
/// cannot be labelled a divergence it no longer exhibits.
fn check_against_ghostkeys(s: &RecordedScenario, r: &CrateResult) {
    let same_visible = r.store.visible() == set(&s.ghostkeys_visible);
    let same_pairs = r.store.complete_pairs() == set(&s.ghostkeys_complete_pairs);
    // Byte-level too, or a divergence that changes a VALUE rather than a key
    // set slips through -- which is exactly what the stale-certificate case
    // does. The crate's own markers are excluded; nothing else is.
    let ghostkeys_store: BTreeMap<Vec<u8>, Vec<u8>> = s
        .ghostkeys_store
        .iter()
        .map(|(k, v)| (unhex(k), unhex(v)))
        .collect();
    let same_bytes = r.store.app_secrets() == ghostkeys_store;
    let agree = same_visible && same_pairs && same_bytes;

    match &s.agreement {
        Agreement::Agree | Agreement::DivergeClassification(_) => assert!(
            agree,
            "`{}` is declared to agree on the store, but the crate produced \
             visible={:?} pairs={:?} same_bytes={same_bytes} against ghostkeys' \
             visible={:?} pairs={:?}",
            s.name,
            r.store.visible(),
            r.store.complete_pairs(),
            s.ghostkeys_visible,
            s.ghostkeys_complete_pairs
        ),
        Agreement::DivergeOutcome(reason) => assert!(
            !agree,
            "`{}` is declared to diverge ({reason}), but the crate now matches the \
             shipped sweep. If the crate has been fixed, the finding must be retired \
             deliberately rather than left asserting something untrue.",
            s.name
        ),
    }
}

// ===========================================================================
// Scenarios
// ===========================================================================

/// **Expected before running:** the crate imports both keys and makes both
/// visible, matching the sweep exactly. This is the case the convergent-design
/// claim rests on, and it holds.
#[test]
fn predecessor_holds_keys_and_exports_them() {
    let s = scenario("predecessor_holds_keys_and_exports_them");
    assert_eq!(s.predecessors[0].ghostkeys_bucket, "Exported(2)");
    assert_eq!(
        set(&s.ghostkeys_visible),
        BTreeSet::from(["fpA".to_string(), "fpB".to_string()]),
        "the sweep's imports are listable"
    );

    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(r.classifications, vec!["Imported"]);
    // The bytes land, and the index even names them...
    assert_eq!(
        r.store.complete_pairs(),
        BTreeSet::from(["fpA".to_string(), "fpB".to_string()])
    );
    assert_eq!(
        r.store.indexed(),
        BTreeSet::from(["fpA".to_string(), "fpB".to_string()])
    );
    // ...but no grant was recorded for either, so `handle_list` shows neither.
    assert!(
        r.store.visible().is_empty(),
        "a raw-pair import grants nothing, so every recovered key is a dead entry"
    );
    for fp in ["fpA", "fpB"] {
        assert!(
            !r.store.secrets.contains_key(&perm_key(fp)),
            "permissions are not among the exported pairs, so no adapter can supply them"
        );
    }
    check_against_ghostkeys(&s, &r);
}

/// **Expected before running:** nothing imported either way. ghostkeys skips
/// before asking for keys (so no private-key dialog fires); the crate probes,
/// fetches an empty set and records `NoData`. Different mechanics, same
/// observable outcome.
#[test]
fn predecessor_registered_but_holds_nothing() {
    let s = scenario("predecessor_registered_but_holds_nothing");
    assert_eq!(s.agreement, Agreement::Agree);
    assert_eq!(s.predecessors[0].ghostkeys_bucket, "SkippedEmpty");

    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(r.classifications, vec!["NoData"]);
    assert!(r.store.visible().is_empty());
    check_against_ghostkeys(&s, &r);
}

/// **Expected before running:** the stores agree, the stories do not.
/// ghostkeys files three distinct buckets for not-registered, silence and an
/// answered failure; `probe_executable` returns a bool, so the crate reports
/// one `Unresponsive` for all three.
///
/// **Divergence (classification):** an adopter reading `any_unresponsive()`
/// gets `true` on essentially every vault open -- silence is the ordinary case
/// -- so the one signal that means "something is there and unreadable" is
/// buried under the eleven that mean nothing.
#[test]
fn three_ghostkeys_buckets_collapse_into_one_unresponsive() {
    let absent = scenario("predecessor_not_registered");
    let failed = scenario("predecessor_answers_with_an_error");

    // ghostkeys told these apart.
    assert_eq!(absent.predecessors[0].ghostkeys_bucket, "not_registered");
    assert_eq!(
        failed.predecessors[0].ghostkeys_bucket,
        "answered_with_error"
    );

    let r_absent = run(&absent, SecretSelectionPolicy::NewestSnapshotWins);
    let r_failed = run(&failed, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(r_absent.classifications, vec!["Unresponsive(no-reply)"]);
    assert_eq!(r_failed.classifications, vec!["Unresponsive(error)"]);
    // Same VARIANT for all three; only a free-text `error` string separates
    // them, and `any_unresponsive()` -- the API an adopter is told to gate on
    // -- cannot see it.
    assert!(r_absent.classifications[0].starts_with("Unresponsive"));
    assert!(r_failed.classifications[0].starts_with("Unresponsive"));
    assert_eq!(
        r_absent.classifications,
        r_silent_absent_shape(),
        "not-registered is reported exactly as silence is: Unresponsive with no error"
    );

    // The third, silence, appears as the newest predecessor of the timeout
    // scenario and is likewise Unresponsive.
    let silent = scenario("predecessor_times_out");
    assert_eq!(silent.predecessors[1].ghostkeys_bucket, "undetermined");
    let r_silent = run(&silent, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(r_silent.classifications[0], "Unresponsive(no-reply)");

    // Stores are unaffected, which is why these are classification-only.
    check_against_ghostkeys(&absent, &r_absent);
    check_against_ghostkeys(&failed, &r_failed);
}

/// **Expected before running:** the important one. Silence is the ORDINARY case
/// (`migration.rs`'s header records nine legacy entries producing nine timeouts
/// on a real node), so the sweep walks straight past it and recovers the older
/// generation's key. `unresponsive_terminates()` is true under
/// `NewestSnapshotWins`, so the crate stops at the first silent predecessor and
/// never probes anything older.
///
/// **Divergence (outcome): key loss under the crate's default policy.**
#[test]
fn newest_snapshot_wins_halts_on_the_first_silence() {
    let s = scenario("predecessor_times_out");
    assert_eq!(s.ghostkeys_visible, vec!["fpOld".to_string()]);

    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(
        r.classifications,
        vec!["Unresponsive(no-reply)", "Superseded"],
        "newest-first: the silent generation halts the walk"
    );
    assert_eq!(
        r.fetched, 0,
        "the G1.8 preflight is what stops a silent predecessor being fetched at all"
    );
    assert_eq!(
        r.probed, 1,
        "the older, data-bearing generation is never probed"
    );
    assert!(
        r.store.complete_pairs().is_empty(),
        "the crate's default policy recovers nothing here -- not even the bytes"
    );
    check_against_ghostkeys(&s, &r);

    // Union does not terminate on Unresponsive, so it does recover the bytes.
    // They are still not listable, for the separate permission reason.
    let u = run(&s, union());
    assert_eq!(
        u.classifications,
        vec!["Unresponsive(no-reply)", "Imported"]
    );
    assert_eq!(u.store.complete_pairs(), set(&s.ghostkeys_complete_pairs));
    assert!(
        u.store.visible().is_empty(),
        "recovered, indexed, and still invisible: no grant was carried"
    );
}

/// **Expected before running:** keys created under two different generations.
/// ghostkeys sweeps every entry and recovers both. `NewestSnapshotWins` stops
/// at the newest data-bearing generation, so the older key is `Superseded`.
///
/// **Divergence (outcome): key loss.** And switching to `UnionAllGenerations`
/// does NOT close it: Union recovers the older key's bytes, but `gk:index` is
/// one never-clobber slot that the newest generation writes first, so the older
/// key stays invisible. No crate policy reproduces the sweep's result here.
#[test]
fn newest_snapshot_wins_strands_an_older_generation() {
    let s = scenario("multiple_generations_newest_already_has_the_data");
    assert_eq!(
        set(&s.ghostkeys_visible),
        BTreeSet::from(["fpNew".to_string(), "fpOld".to_string()])
    );

    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(
        r.classifications,
        vec!["Imported", "Superseded", "Superseded"],
        "newest-first, stopping at the first data-bearing generation"
    );
    assert_eq!(
        r.store.complete_pairs(),
        BTreeSet::from(["fpNew".to_string()]),
        "fpOld is stranded"
    );
    check_against_ghostkeys(&s, &r);

    let u = run(&s, union());
    assert_eq!(u.classifications, vec!["Imported", "NoData", "Imported"]);
    assert_eq!(
        u.store.complete_pairs(),
        BTreeSet::from(["fpNew".to_string(), "fpOld".to_string()]),
        "Union does fix the SELECTION divergence"
    );
    assert_eq!(
        u.store.indexed(),
        BTreeSet::from(["fpNew".to_string()]),
        "but the older generation's index write is clobber-skipped, so fpOld is not listed"
    );
    assert!(
        u.store.visible().is_empty(),
        "and neither generation carries a grant, so nothing is listable regardless"
    );
}

/// **Expected before running:** ghostkeys' module header argues at length that
/// no available signal justifies a "migration done" flag, because
/// `ExportAllGhostKeys` silently skips keys the caller lacks `Export` scope on
/// and the reply carries no count to check against. The crate writes a
/// `pred-done` marker even for a predecessor that exported NOTHING, and
/// short-circuits it forever after.
///
/// **Divergence (outcome):** a first, empty pass seals the predecessor. When it
/// later hands over a key -- scope granted, or a missed dialog answered -- the
/// sweep recovers it and the crate does not even probe.
#[test]
fn an_empty_predecessor_is_sealed_by_its_marker() {
    let later = scenario("predecessor_gains_data_after_an_empty_answer");
    assert_eq!(later.predecessors[0].ghostkeys_bucket, "Exported(1)");
    assert_eq!(later.ghostkeys_visible, vec!["fpLate".to_string()]);

    // Pass 1: the same predecessor, answering empty. Taken from the
    // registered-but-empty recording so the emptiness is ghostkeys' own, but
    // re-keyed onto this scenario's predecessor identity.
    let mut empty_first = later.predecessors.clone();
    let empty = scenario("predecessor_registered_but_holds_nothing");
    empty_first[0].probe = empty.predecessors[0].probe.clone();
    empty_first[0].fetch = empty.predecessors[0].fetch.clone();

    let first = run_over(
        &empty_first,
        Namespace::default(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(first.classifications, vec!["NoData"]);
    assert!(first.store.visible().is_empty());

    // Pass 2 over the store pass 1 left behind, with the predecessor now
    // exporting.
    let second = run_over(
        &later.predecessors,
        first.store.clone(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(
        second.classifications,
        vec!["AlreadyMigrated"],
        "the empty marker written in pass 1 seals the predecessor"
    );
    assert_eq!(second.probed, 0, "not even probed on the re-run");
    assert!(
        second.store.visible().is_empty(),
        "fpLate is never recovered by the crate"
    );
    check_against_ghostkeys(&later, &second);

    // Union does not rescue it either: the marker gate precedes the policy.
    let union_second = run_over(&later.predecessors, first.store, union());
    assert_eq!(union_second.classifications, vec!["AlreadyMigrated"]);
    assert!(union_second.store.visible().is_empty());
}

/// **Expected before running:** the successor lists `fpA` because its
/// certificate loaded, but the certificate is stale and the signing key is
/// gone. ghostkeys re-imports unconditionally, overwriting both halves. The
/// crate's import is never-clobber: it writes the absent signing key and keeps
/// the stale certificate.
///
/// **Divergence (outcome):** the stale certificate survives.
#[test]
fn never_clobber_leaves_a_stale_certificate() {
    let s = scenario("successor_holds_a_half_broken_key");
    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);

    assert_eq!(
        r.store.get(&cert_key("fpA")),
        Some(b"STALE-CERT".as_slice()),
        "never-clobber keeps the successor's stale certificate"
    );
    assert!(
        r.store.get(&sk_key("fpA")).is_some(),
        "the missing half IS written"
    );
    check_against_ghostkeys(&s, &r);
}

/// **Expected before running:** the most severe finding. `gk:index` is a single
/// CBOR secret and `ListGhostKeys` reads it, so a key whose `gk:cert:`/`gk:sk:`
/// pair is stored but whose fingerprint is not in the index does not exist as
/// far as the user is concerned. The successor already has an index (the user
/// made a key on the new version before the sweep ran), so the predecessor's
/// index write is skipped by never-clobber.
///
/// **Divergence (outcome): silent, total loss of the recovered key from the
/// user's point of view**, with both halves sitting in the store.
#[test]
fn recovered_keys_are_invisible_when_the_successor_already_has_an_index() {
    let s = scenario("imported_keys_are_visible_to_the_user");
    assert_eq!(
        set(&s.ghostkeys_visible),
        BTreeSet::from(["fpMine".to_string(), "fpOld".to_string()]),
        "the sweep's import handler appends to the index"
    );

    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(r.classifications, vec!["Imported"]);
    assert_eq!(
        r.store.complete_pairs(),
        BTreeSet::from(["fpMine".to_string(), "fpOld".to_string()]),
        "both halves of fpOld ARE written"
    );
    assert_eq!(
        r.store.indexed(),
        BTreeSet::from(["fpMine".to_string()]),
        "but gk:index was skipped by never-clobber, so fpOld is not even listed"
    );
    assert_eq!(
        r.store.visible(),
        BTreeSet::from(["fpMine".to_string()]),
        "only the user's own pre-existing key, which already had its grant, stays listable"
    );
    check_against_ghostkeys(&s, &r);
}

/// **Expected before running:** what the SECOND re-key after adopting the crate
/// looks like. The predecessor's namespace dump still carries the `pred-done`
/// marker it wrote when it was the successor of an earlier generation, and the
/// crate documents that markers must never be swept forward. It strips them, so
/// the app-visible store matches the sweep's exactly.
///
/// This is the one place the crate does something ghostkeys does not have to:
/// ghostkeys never sees a marker at all, because it migrates through
/// `ImportGhostKey` rather than copying raw pairs. The strip is correct -- the
/// scenario's overall outcome still diverges, because the recovered key carries
/// no permission grant like every other recovering scenario.
#[test]
fn a_stale_migration_marker_is_not_swept_forward() {
    let s = scenario("predecessor_carries_a_stale_migration_marker");
    // The marker strip itself is correct; the scenario still diverges, for the
    // permission reason every recovering scenario does.
    assert!(matches!(s.agreement, Agreement::DivergeOutcome(_)));

    // The fixture's stale key really is in the crate's reserved namespace --
    // otherwise this would be testing an ordinary secret and the strip would
    // never be exercised.
    let stale: Vec<Vec<u8>> = s.predecessors[0]
        .fetch
        .as_ref()
        .expect("the predecessor exports")
        .iter()
        .map(|(k, _)| unhex(k))
        .filter(|k| k.starts_with(PRED_DONE_MARKER_KEY_PREFIX))
        .collect();
    assert_eq!(
        stale.len(),
        1,
        "the fixture must dump exactly one completion marker, in the crate's own \
         reserved namespace ({PRED_DONE_MARKER_KEY_PREFIX:?})"
    );

    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(r.classifications, vec!["Imported"]);
    assert!(
        !r.store.secrets.contains_key(&stale[0]),
        "the predecessor's completion marker must not be swept into the successor"
    );
    check_against_ghostkeys(&s, &r);
}

/// **Expected before running:** one storage failure on the NEWEST predecessor.
/// ghostkeys counts a failed import, warns, and carries on to recover the older
/// generation. The crate returns `Incomplete` and sets `terminated = true`
/// **unconditionally** (`delegate_migrate.rs:783`), so every older generation
/// is `Superseded`.
///
/// **Divergence (outcome), and it survives the policy switch** -- the crate's
/// own `incomplete_newer_halts_before_older_under_both_policies` pins the
/// unconditional halt for Union too, so unlike D1 and D2 there is no policy
/// that recovers from this.
#[test]
fn one_failed_write_supersedes_every_older_generation() {
    let s = scenario("a_failed_write_on_the_newest_predecessor");
    assert_eq!(
        s.ghostkeys_failed_imports, 1,
        "the sweep counts the failure"
    );
    assert_eq!(
        set(&s.ghostkeys_visible),
        BTreeSet::from(["fpGood".to_string()]),
        "and still recovers the older generation"
    );

    // 0.5.0 CHANGED THIS, and the change is the D8 fix this differential asked
    // for: termination now derives from the policy, so a data-bearing
    // `Incomplete` halts `NewestSnapshotWins` (unchanged) but the Union walk
    // CONTINUES to the intact older generation. The 0.4.0 behaviour -- one
    // storage failure on one key of the newest predecessor superseding every
    // older generation under BOTH policies -- is gone.
    let nsw = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(
        nsw.classifications,
        vec!["Incomplete", "Superseded"],
        "NewestSnapshotWins still halts on a data-bearing partial write"
    );
    assert!(nsw.store.visible().is_empty());

    let u = run(&s, union());
    assert_eq!(
        u.classifications,
        vec!["Incomplete", "Imported"],
        "0.5.0 Union walks on past the partial write to the older generation"
    );
    // The older generation's key IS recovered now -- but through the raw-pair
    // writer it lands without grants, so it is still invisible: the D9 half of
    // the finding stands for a raw copy, and only the seam writer clears it.
    assert!(
        u.store.visible().is_empty(),
        "raw pairs recover the bytes but grant nothing"
    );
    assert_eq!(
        u.store.complete_pairs(),
        BTreeSet::from(["fpGood".to_string()]),
        "both halves of the older generation's key are in the store"
    );
    check_against_ghostkeys(&s, &nsw);
}

/// **Expected before running:** the predecessor SAYS it holds identities and
/// then exports none, because this vault lacks `Export` scope on them.
/// ghostkeys files `present_but_unexportable` and warns; the crate cannot tell
/// it from a genuinely empty predecessor, records `NoData`, and writes an empty
/// completion marker that seals it forever.
///
/// **Divergence (classification), and the worst instance of the marker bug:**
/// keys known to exist and be unreachable are recorded as "nothing here" and
/// then never asked for again.
#[test]
fn keys_known_to_exist_are_recorded_as_no_data_and_sealed() {
    let s = scenario("predecessor_holds_keys_but_exports_nothing");
    assert_eq!(
        s.predecessors[0].ghostkeys_bucket, "present_but_unexportable",
        "the sweep knows the keys are there and unreachable"
    );

    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(
        r.classifications,
        vec!["NoData"],
        "the crate cannot distinguish this from an empty predecessor"
    );

    // Indistinguishable from the genuinely-empty case, which is the point.
    let empty = scenario("predecessor_registered_but_holds_nothing");
    let r_empty = run(&empty, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(r.classifications, r_empty.classifications);
    assert_ne!(
        s.predecessors[0].ghostkeys_bucket, empty.predecessors[0].ghostkeys_bucket,
        "ghostkeys tells them apart, and warns about one of them"
    );

    // And the marker is now written, so a later pass will not re-ask.
    let again = run_over(
        &s.predecessors,
        r.store.clone(),
        SecretSelectionPolicy::NewestSnapshotWins,
    );
    assert_eq!(again.classifications, vec!["AlreadyMigrated"]);
    assert_eq!(again.probed, 0);

    check_against_ghostkeys(&s, &r);
}

/// **Expected before running:** it announced keys and then went quiet -- the
/// shape of a missed confirmation dialog, which ghostkeys files as
/// `present_but_silent` and tells the user to reload and allow. The crate
/// reports the same `Unresponsive(no-reply)` it reports for the eleven entries
/// the node simply does not have.
#[test]
fn a_predecessor_that_announced_keys_then_went_quiet_is_bucketed_with_absence() {
    let s = scenario("predecessor_holds_keys_then_goes_silent");
    assert_eq!(s.predecessors[0].ghostkeys_bucket, "present_but_silent");

    // It answered the preflight, so the fetch is what times out -- reported as
    // `Unresponsive(error)`, exactly like a delegate that answered with a
    // failure, and unlike ghostkeys' `present_but_silent`, which has its own
    // user-facing message ("reload the vault and allow the prompt").
    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(r.classifications, vec!["Unresponsive(error)"]);

    let failed = scenario("predecessor_answers_with_an_error");
    let r_failed = run(&failed, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(
        r.classifications, r_failed.classifications,
        "indistinguishable from a delegate-level failure, though the remedy differs"
    );
    check_against_ghostkeys(&s, &r);
}

/// **Expected before running:** a local transport failure means nothing was
/// asked, so nothing was learned. ghostkeys deliberately files it with silence
/// -- warning here would put a red toast in front of a user whose websocket
/// dropped, while the connection banner already says so. The crate attaches the
/// error string, so it reads as evidence that something answered.
#[test]
fn a_local_transport_failure_reads_as_an_answer() {
    let s = scenario("the_request_never_left_the_browser");
    assert_eq!(
        s.predecessors[0].ghostkeys_bucket, "undetermined",
        "ghostkeys files it with silence, on purpose"
    );

    let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(
        r.classifications,
        vec!["Unresponsive(error)"],
        "the crate marks it as having errored, like a delegate that answered badly"
    );

    let failed = scenario("predecessor_answers_with_an_error");
    let r_failed = run(&failed, SecretSelectionPolicy::NewestSnapshotWins);
    assert_eq!(
        r.classifications, r_failed.classifications,
        "indistinguishable from a genuine delegate-level failure"
    );
    check_against_ghostkeys(&s, &r);
}

// ===========================================================================
// Meta
// ===========================================================================

/// Every recorded scenario must be exercised by a test above, so a scenario
/// cannot be added on the ghostkeys side and silently never replayed here.
#[test]
fn every_recorded_scenario_is_replayed() {
    let src = include_str!("differential.rs");
    for s in observations().scenarios {
        assert!(
            src.contains(&format!("scenario(\"{}\")", s.name)),
            "recorded scenario `{}` is never replayed through the crate",
            s.name
        );
    }
}

/// Every scenario's declared agreement must hold under the crate's default
/// policy. This is the table from the PR body, executable: a `DivergeOutcome`
/// row asserts the stores really do differ, and an `Agree` row asserts they do
/// not, so neither label can quietly become untrue.
#[test]
fn every_declared_agreement_holds() {
    for s in observations().scenarios {
        // The sealed-marker scenario needs its first, empty pass to exhibit the
        // divergence; `an_empty_predecessor_is_sealed_by_its_marker` covers it.
        if s.name == "predecessor_gains_data_after_an_empty_answer" {
            continue;
        }
        let r = run(&s, SecretSelectionPolicy::NewestSnapshotWins);
        check_against_ghostkeys(&s, &r);
    }
}

/// `MigrationAuthorization` is a compile-time forcing function with an empty
/// runtime arm -- sound at this boundary, since the caller is the app's own
/// client code rather than a network-reachable RPC. The whole cost of it is one
/// explicit call, which makes it the only item on the adoption ledger that is
/// free.
#[test]
fn the_authorization_gate_costs_one_call() {
    assert_eq!(
        MigrationAuthorization::app_author_ack(),
        MigrationAuthorization::app_author_ack()
    );
}

/// The index decoder must fail loudly rather than report an empty index, or a
/// misread would look exactly like the invisibility bug it is used to detect.
#[test]
fn the_index_decoder_rejects_anything_it_does_not_understand() {
    assert_eq!(
        decode_cbor_string_array(&[0x82, 0x63, b'f', b'p', b'A', 0x63, b'f', b'p', b'B']),
        Some(vec!["fpA".to_string(), "fpB".to_string()])
    );
    assert_eq!(decode_cbor_string_array(&[0x80]), Some(vec![]));
    // A map, an int array, and a truncated string are all rejected.
    assert_eq!(decode_cbor_string_array(&[0xa1, 0x01, 0x02]), None);
    assert_eq!(decode_cbor_string_array(&[0x81, 0x01]), None);
    assert_eq!(decode_cbor_string_array(&[0x81, 0x63, b'f']), None);
    // Trailing bytes are rejected too.
    assert_eq!(decode_cbor_string_array(&[0x80, 0x00]), None);
}

/// The `DelegateKey` this crate builds from a recorded registry row must be the
/// key ghostkeys recorded -- the differential's only cross-version conversion.
#[test]
fn recorded_registry_rows_round_trip_to_delegate_keys() {
    let s = scenario("predecessor_holds_keys_and_exports_them");
    let p = &s.predecessors[0];
    let key = DelegateKey::new(
        unhex32(&p.delegate_key),
        CodeHash::new(unhex32(&p.code_hash)),
    );
    assert_eq!(key.bytes(), unhex32(&p.delegate_key));
}

// ===========================================================================
// Where the 0.5.0 writer-seam measurement lives now
// ===========================================================================
//
// The 2026-08-11 re-measurement first ran here as a MODEL of the adapter a
// ghostkeys adopter would write (`mod seam`, preserved on the experiment
// branch `gk-05-remeasure-experiment`): all 14 recorded scenarios matched the
// shipped sweep through a `SuccessorSecretsIo` writer routing imports through
// the app's own import path. The adoption PR replaced that model with the
// REAL adapter, and the measurement moved with it:
// `ui/src/migration_adapter_differential.rs` drives the actual shipped
// `GkPredecessorIo`/`GkSuccessorIo` over the same fixtures and asserts
// agreement with the same committed record. Keeping a second, modelled copy
// here would drift from the real adapter; this crate's remaining job is the
// raw-pair HALF of the differential above — the documented reason a raw
// `(key, value)` copy was rejected for ghostkeys.
