//! Differential test of the REAL `freenet-migrate` adapter
//! (`migration_adapter.rs`) against the recorded behaviour of the outgoing
//! hand-rolled sweep.
//!
//! # How the two halves fit
//!
//! * `migration_differential.rs` holds the FIXTURES (real registry rows, real
//!   `GhostkeyResponse` replies, the modelled successor namespace) and the
//!   ORACLE — a transcription of the outgoing sweep whose outputs are frozen
//!   into `tests/migration-differential/observations.json` and re-verified on
//!   every run.
//! * This module drives the SAME fixtures through the REAL adapter — the
//!   actual `GkPredecessorIo` / `GkSuccessorIo` / `run_crate_migration` that
//!   ship in the vault — over a mock [`GkDelegateChannel`] whose
//!   current-delegate end behaves like `handlers.rs::handle_import`
//!   (via the shared `Namespace::apply_import` model), and asserts agreement
//!   with the COMMITTED record, mechanically.
//!
//! Expectations come from the committed JSON rather than a live oracle run on
//! purpose: the record is frozen, so a mutation to the shared model or to the
//! adapter turns tests red instead of moving both sides of the comparison at
//! once. (`the_recorded_observations_match_the_shipped_sweep` separately pins
//! the record to the live transcription.)
//!
//! # The measured result this suite pins
//!
//! Re-measured 2026-08-11 against freenet-migrate 0.5.0: all 14 recorded
//! scenarios MATCH the shipped sweep on visible key set, complete cert+sk
//! pairs, recovered/failed counts, and store bytes. (Under 0.4.0's raw pair
//! copy, 13 of the same 14 diverged.) The deliberate residual divergences —
//! `gk:index` order and label newest-wins on a shared fingerprint — are each
//! pinned by name below.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use freenet_migrate::PredecessorMigration;
use freenet_stdlib::prelude::{CodeHash, DelegateKey};
use futures::executor::block_on;
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

use crate::api::delegate::DelegateCallError;
use crate::migration::MigrationOutcome;
use crate::migration_adapter::{run_crate_migration, GkDelegateChannel};
use crate::migration_differential::{
    key, label_key, legacy_entries, predecessors, scenarios, sk_key, Key, Namespace, Observations,
    Predecessor, PredecessorState, RecordedScenario, Scenario, INDEX_KEY, OBSERVATIONS_PATH,
};

// ---------------------------------------------------------------------------
// The mock node: predecessors answer from fixtures, the current delegate
// applies imports the way handlers.rs::handle_import does
// ---------------------------------------------------------------------------

/// The synthetic current delegate key for native runs. Must not collide with
/// any registry row (those are BLAKE3 outputs; this is a constant pattern).
fn current_key() -> DelegateKey {
    DelegateKey::new([0xCCu8; 32], CodeHash::new([0xCCu8; 32]))
}

/// The fixtures encode a certificate as `-----BEGIN
/// GHOSTKEY_CERTIFICATE-----{fp}`, so "the delegate derives the fingerprint
/// from the certificate" is modelled by stripping that prefix — which is also
/// what lets a fixture express an exported-metadata fingerprint that DIFFERS
/// from the derived one (the mis-echo case).
const CERT_PREFIX: &str = "-----BEGIN GHOSTKEY_CERTIFICATE-----";

struct MockNode {
    current: DelegateKey,
    /// Behind a `RefCell` so a test can change what a predecessor answers
    /// BETWEEN walks (the durable-marker contrast needs "empty on run 1,
    /// data-bearing on run 2" against one channel borrow).
    preds: RefCell<BTreeMap<Vec<u8>, PredecessorState>>,
    /// What each predecessor answers `GetDefaultKey` with.
    pred_defaults: BTreeMap<Vec<u8>, Option<String>>,
    ns: RefCell<Namespace>,
    /// `ExportAllGhostKeys` sends per predecessor — the never-prompt pin.
    export_sends: RefCell<BTreeMap<Vec<u8>, usize>>,
    /// `ImportGhostKey` sends to the current delegate.
    import_sends: RefCell<usize>,
    /// `SetLabel` calls the adapter made, in order.
    labels_set: RefCell<Vec<(String, String)>>,
    /// `SetDefaultKey` calls the adapter made, in order.
    defaults_set: RefCell<Vec<String>>,
    /// Fingerprints whose `ImportGhostKey` round-trip fails at TRANSPORT
    /// level (timeout / dead socket) rather than with a delegate answer.
    import_transport_fail: BTreeSet<String>,
}

impl MockNode {
    fn new(preds: &[Predecessor], initial: Namespace) -> Self {
        Self {
            current: current_key(),
            preds: RefCell::new(
                preds
                    .iter()
                    .map(|p| (p.entry.delegate_key.to_vec(), p.state.clone()))
                    .collect(),
            ),
            pred_defaults: BTreeMap::new(),
            ns: RefCell::new(initial),
            export_sends: RefCell::new(BTreeMap::new()),
            import_sends: RefCell::new(0),
            labels_set: RefCell::new(Vec::new()),
            defaults_set: RefCell::new(Vec::new()),
            import_transport_fail: BTreeSet::new(),
        }
    }

    /// The generated-table shape for these predecessors, oldest first.
    fn table(preds: &[Predecessor]) -> Vec<([u8; 32], [u8; 32])> {
        preds
            .iter()
            .map(|p| (p.entry.delegate_key, p.entry.code_hash))
            .collect()
    }

    /// `handlers.rs::handle_import`, at the wire: derive the fingerprint from
    /// the certificate, refuse when storage refuses the grant, apply the
    /// import (cert + sk + index + full grant — via the SAME
    /// `Namespace::apply_import` model the oracle uses), echo the derived
    /// fingerprint. The request carries no label; labelling is `SetLabel`'s
    /// job, exactly as in the real delegate.
    fn handle_import(
        &self,
        certificate_pem: String,
        signing_key_pem: String,
    ) -> Result<GhostkeyResponse, DelegateCallError> {
        *self.import_sends.borrow_mut() += 1;
        let Some(derived) = certificate_pem
            .strip_prefix(CERT_PREFIX)
            .map(str::to_string)
        else {
            return Ok(GhostkeyResponse::Error {
                message: "invalid certificate PEM: unrecognized armor".to_string(),
            });
        };
        if self.import_transport_fail.contains(&derived) {
            // The reply never arrives; the vault's call times out.
            return Err(DelegateCallError::TimedOut);
        }
        let mut ns = self.ns.borrow_mut();
        let imported = ns.apply_import(&Key {
            fp: derived.clone(),
            cert: certificate_pem,
            sk: signing_key_pem,
            label: None,
        });
        if !imported {
            // The real handler checks only the grant write and answers an
            // explicit error when it fails.
            return Ok(GhostkeyResponse::Error {
                message: "imported the ghostkey but could not record ownership of it".into(),
            });
        }
        Ok(GhostkeyResponse::ImportResult {
            fingerprint: derived,
            notary_info: "Freenet Notary".to_string(),
        })
    }
}

impl GkDelegateChannel for MockNode {
    async fn call(
        &self,
        target: &DelegateKey,
        request: GhostkeyRequest,
        _timeout_secs: u64,
    ) -> Result<GhostkeyResponse, DelegateCallError> {
        if *target == self.current {
            return match request {
                GhostkeyRequest::ImportGhostKey {
                    certificate_pem,
                    signing_key_pem,
                } => self.handle_import(certificate_pem, signing_key_pem),
                GhostkeyRequest::SetLabel { fingerprint, label } => {
                    self.ns
                        .borrow_mut()
                        .secrets
                        .insert(label_key(&fingerprint), label.clone().into_bytes());
                    self.labels_set
                        .borrow_mut()
                        .push((fingerprint.clone(), label.clone()));
                    Ok(GhostkeyResponse::LabelSet { fingerprint, label })
                }
                GhostkeyRequest::SetDefaultKey { fingerprint } => {
                    self.defaults_set.borrow_mut().push(fingerprint.clone());
                    Ok(GhostkeyResponse::DefaultKeySet { fingerprint })
                }
                other => Ok(GhostkeyResponse::Error {
                    message: format!("unexpected request to the current delegate: {other:?}"),
                }),
            };
        }

        let bytes = target.bytes().to_vec();
        let Some(state) = self.preds.borrow().get(&bytes).cloned() else {
            return Err(DelegateCallError::Transport(
                "request to a delegate outside the fixture".into(),
            ));
        };
        match request {
            GhostkeyRequest::HasIdentity => state.presence_reply(),
            GhostkeyRequest::ExportAllGhostKeys => {
                *self.export_sends.borrow_mut().entry(bytes).or_insert(0) += 1;
                state.export_reply()
            }
            GhostkeyRequest::GetDefaultKey => Ok(GhostkeyResponse::DefaultKeyResult {
                fingerprint: self.pred_defaults.get(&bytes).cloned().flatten(),
            }),
            other => Ok(GhostkeyResponse::Error {
                message: format!("unexpected request to a predecessor: {other:?}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Driving the real adapter
// ---------------------------------------------------------------------------

struct AdapterRun {
    outcome: MigrationOutcome,
    report: freenet_migrate::DelegateMigrationReport,
    imported: Vec<GhostKeyInfo>,
}

fn run_adapter(
    node: &MockNode,
    preds: &[Predecessor],
    already_held: Option<Vec<String>>,
) -> AdapterRun {
    let table = MockNode::table(preds);
    let mut imported = Vec::new();
    let (outcome, report) = block_on(run_crate_migration(
        node,
        &current_key(),
        &table,
        already_held,
        |info| imported.push(info),
    ));
    AdapterRun {
        outcome,
        report,
        imported,
    }
}

/// Run the real adapter over a scenario the way the vault would: initial
/// store from the fixture, `already_held` = what the current delegate lists.
fn run_scenario(s: &Scenario) -> (MockNode, AdapterRun) {
    let node = MockNode::new(&s.preds, s.initial.clone());
    let held: Vec<String> = s.initial.visible().into_iter().collect();
    let run = run_adapter(&node, &s.preds, Some(held));
    (node, run)
}

// ---------------------------------------------------------------------------
// Comparing against the committed record
// ---------------------------------------------------------------------------

fn committed_observations() -> Observations {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(OBSERVATIONS_PATH);
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&json).expect("the committed observations must parse")
}

fn recorded(name: &str) -> RecordedScenario {
    committed_observations()
        .scenarios
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no recorded scenario named `{name}`"))
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn set(items: &[String]) -> BTreeSet<String> {
    items.iter().cloned().collect()
}

/// The counters the recorded per-predecessor buckets imply. `SkippedEmpty`
/// and `Exported(n)` move no counter; every other bucket IS a counter name.
fn expected_counters(rec: &RecordedScenario) -> BTreeMap<&'static str, usize> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for p in &rec.predecessors {
        for name in [
            "undetermined",
            "answered_with_error",
            "present_but_unexportable",
            "present_but_silent",
            "not_registered",
            "unsettled_and_empty",
        ] {
            if p.ghostkeys_bucket == name {
                *counts.entry(name).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Store-level and counter-level agreement with the recorded sweep output.
///
/// `gk:index` is compared as a SET: the sweep walked generations oldest-first
/// and appended, the crate walks newest-first, so a multi-generation recovery
/// lists the same fingerprints in a different order. That ordering is the one
/// residual store difference across all recorded scenarios; it is asserted
/// explicitly by `the_only_residual_store_difference_is_index_order`.
fn assert_matches_recorded(name: &str, node: &MockNode, run: &AdapterRun) {
    let rec = recorded(name);
    let ns = node.ns.borrow();

    assert_eq!(
        ns.visible(),
        set(&rec.ghostkeys_visible),
        "`{name}`: visible set differs from the shipped sweep"
    );
    assert_eq!(
        ns.complete_pairs(),
        set(&rec.ghostkeys_complete_pairs),
        "`{name}`: complete cert+sk pairs differ from the shipped sweep"
    );
    assert_eq!(
        ns.indexed(),
        set(&rec.ghostkeys_indexed),
        "`{name}`: gk:index membership differs from the shipped sweep"
    );

    let strip_index = |m: BTreeMap<Vec<u8>, Vec<u8>>| {
        let mut m = m;
        m.remove(INDEX_KEY);
        m
    };
    let recorded_store: BTreeMap<Vec<u8>, Vec<u8>> = rec
        .ghostkeys_store
        .iter()
        .map(|(k, v)| (unhex(k), unhex(v)))
        .collect();
    assert_eq!(
        strip_index(ns.secrets.clone()),
        strip_index(recorded_store),
        "`{name}`: store bytes (index aside) differ from the shipped sweep"
    );

    assert_eq!(
        (run.outcome.recovered, run.outcome.failed_imports),
        (rec.ghostkeys_recovered, rec.ghostkeys_failed_imports),
        "`{name}`: recovered/failed counts differ from the shipped sweep"
    );

    let expected = expected_counters(&rec);
    let actual: BTreeMap<&'static str, usize> = [
        ("undetermined", run.outcome.undetermined),
        ("answered_with_error", run.outcome.answered_with_error),
        (
            "present_but_unexportable",
            run.outcome.present_but_unexportable,
        ),
        ("present_but_silent", run.outcome.present_but_silent),
        ("not_registered", run.outcome.not_registered),
        ("unsettled_and_empty", run.outcome.unsettled_and_empty),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .collect();
    assert_eq!(
        actual, expected,
        "`{name}`: the user-facing counters differ from the shipped sweep's buckets"
    );
}

// ===========================================================================
// THE HEADLINE
// ===========================================================================

/// Every recorded scenario, replayed through the REAL adapter over the mock
/// node, produces the same visible set, the same complete pairs, the same
/// store bytes (index order aside), and the same user-facing counters as the
/// shipped hand-rolled sweep. Under freenet-migrate 0.4.0's raw pair copy,
/// 13 of these 14 diverged; the 0.5.0 writer seam is what closes them.
#[test]
fn every_recorded_scenario_matches_through_the_real_adapter() {
    let mut names = Vec::new();
    for s in scenarios() {
        let (node, run) = run_scenario(&s);
        assert_matches_recorded(s.name, &node, &run);
        names.push(s.name);
    }
    assert!(
        names.len() >= 14,
        "expected all 14 recorded scenarios, ran {}",
        names.len()
    );
}

// ===========================================================================
// The never-prompt pins
// ===========================================================================

/// An empty predecessor is skipped WITHOUT `ExportAllGhostKeys`: delegates
/// from entry 12 onward raise a private-key confirmation dialog on export
/// (and old delegates may prompt unconditionally), so exporting from the
/// eleven-ish empty legacy entries would put unexplained dialogs in front of
/// the user on every vault open.
#[test]
fn an_empty_predecessor_is_never_asked_for_keys() {
    let preds = predecessors(vec![PredecessorState::RegisteredButEmpty]);
    let node = MockNode::new(&preds, Namespace::default());
    let run = run_adapter(&node, &preds, Some(vec![]));
    assert!(
        node.export_sends.borrow().is_empty(),
        "ExportAllGhostKeys was sent to an empty predecessor"
    );
    assert!(matches!(
        run.report.predecessors[0],
        PredecessorMigration::NoData { .. }
    ));
}

/// A silent predecessor gets no export either — the probe already failed, so
/// sending the export would burn the 90s human-scale deadline per absent
/// entry AND risk a dialog.
#[test]
fn a_silent_predecessor_is_never_asked_for_keys() {
    let preds = predecessors(vec![
        PredecessorState::Silent,
        PredecessorState::NotRegistered,
    ]);
    let node = MockNode::new(&preds, Namespace::default());
    let run = run_adapter(&node, &preds, Some(vec![]));
    assert!(
        node.export_sends.borrow().is_empty(),
        "ExportAllGhostKeys was sent to a predecessor that never answered the probe"
    );
    assert_eq!(run.outcome.undetermined, 1);
    assert_eq!(run.outcome.not_registered, 1);
}

// ===========================================================================
// Silence is never absence (the freenet-migrate#19 override)
// ===========================================================================

/// A predecessor that SAID it holds identities and then never answered the
/// export must be reported `Unresponsive` — never `NoData`. `NoData` writes
/// an empty completion marker; page-lifetime markers bound the damage to one
/// run, but the user-facing counter (`present_but_silent`) and the report
/// classification must still tell the truth.
#[test]
fn silence_after_a_presence_claim_is_unresponsive_not_no_data() {
    let preds = predecessors(vec![PredecessorState::HoldsThenSilent]);
    let node = MockNode::new(&preds, Namespace::default());
    let run = run_adapter(&node, &preds, Some(vec![]));
    assert!(
        matches!(
            run.report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ),
        "a fetch timeout must be Unresponsive, got {:?}",
        run.report.predecessors[0]
    );
    assert_eq!(run.outcome.present_but_silent, 1);
    assert!(node.ns.borrow().visible().is_empty());
}

// ===========================================================================
// Page-lifetime markers (the D4 pin)
// ===========================================================================

/// A predecessor sealed empty in one pass is probed again on the next pass —
/// a fresh page load builds a fresh writer, so nothing carries over — and the
/// late-appearing data is recovered. This is the sweep's re-ask-every-startup
/// doctrine surviving the crate adoption.
#[test]
fn a_fresh_run_reprobes_a_predecessor_sealed_empty_last_run() {
    let entries = legacy_entries();
    let empty = predecessors(vec![PredecessorState::RegisteredButEmpty]);
    let node1 = MockNode::new(&empty, Namespace::default());
    let run1 = run_adapter(&node1, &empty, Some(vec![]));
    assert!(matches!(
        run1.report.predecessors[0],
        PredecessorMigration::NoData { .. }
    ));
    assert!(node1.ns.borrow().visible().is_empty());

    // Same registry row, same store, NEXT page load: the delegate now
    // exports a key (the user granted Export scope, or a newer app imported
    // one — `ExportAllGhostKeys` silently skips unexportable keys, so "empty
    // then not" is a real sequence, not a contrivance).
    let later = predecessors(vec![PredecessorState::TooOldButExports(vec![key(
        "fpLate", None,
    )])]);
    assert_eq!(later[0].entry.delegate_key, entries[0].delegate_key);
    let store_after_run1 = node1.ns.borrow().clone();
    let node2 = MockNode::new(&later, store_after_run1);
    let run2 = run_adapter(&node2, &later, Some(vec![]));
    assert!(matches!(
        run2.report.predecessors[0],
        PredecessorMigration::Imported { .. }
    ));
    assert_eq!(
        node2.ns.borrow().visible(),
        BTreeSet::from(["fpLate".to_string()]),
        "the late data must be recovered on the next page load"
    );
}

/// The contrast that justifies the durable-marker BAN: if markers survived
/// across passes, the same predecessor would be sealed by its empty marker
/// and the late data lost until someone noticed — the ghostkeys#32 D4
/// failure, verbatim. Simulated here by reusing one writer (and so one marker
/// map) across two walks. This behaviour must never become reachable in
/// production code; `migration_adapter::tests::markers_have_no_durable_home`
/// pins the absence of the storage mechanisms it would need.
#[test]
fn a_durable_marker_would_seal_the_late_data_away() {
    use crate::migration_adapter::{GkPredecessorIo, GkSuccessorIo};
    use freenet_migrate::{migrate_delegate_secrets, MigrationAuthorization};

    let empty = predecessors(vec![PredecessorState::RegisteredButEmpty]);
    let table = MockNode::table(&empty);
    let lineage = crate::migration_adapter::lineage_from_table(&table, &current_key());
    let entry_key = empty[0].entry.delegate_key.to_vec();

    let node = MockNode::new(&empty, Namespace::default());
    let mut writer = GkSuccessorIo::new(&node, current_key(), Some(vec![]), |_| {});
    let mut reader = GkPredecessorIo::new(&node);
    block_on(migrate_delegate_secrets(
        &mut writer,
        &mut reader,
        &lineage,
        MigrationAuthorization::app_author_ack(),
        crate::migration_adapter::gk_secret_policy(),
    ));

    // The predecessor now HAS data — and the same writer walks again, i.e.
    // its markers held durable across "page loads".
    node.preds.borrow_mut().insert(
        entry_key,
        PredecessorState::TooOldButExports(vec![key("fpLate", None)]),
    );
    let mut reader2 = GkPredecessorIo::new(&node);
    let report = block_on(migrate_delegate_secrets(
        &mut writer,
        &mut reader2,
        &lineage,
        MigrationAuthorization::app_author_ack(),
        crate::migration_adapter::gk_secret_policy(),
    ));
    assert!(
        matches!(
            report.predecessors[0],
            PredecessorMigration::AlreadyMigrated { .. }
        ),
        "durable markers seal the predecessor: {:?}",
        report.predecessors[0]
    );
    assert!(
        node.ns.borrow().visible().is_empty(),
        "fpLate is sealed away exactly as ghostkeys#32 D4 described — which is why \
         durable markers are banned"
    );
}

// ===========================================================================
// Failed imports (the one-token Err → AlreadyAuthoritative mistake)
// ===========================================================================

/// A failed import reports `Incomplete` with a counted failure, and the walk
/// continues to older generations (Union). Mapping the failure onto
/// `AlreadyAuthoritative` instead would seal the predecessor clean and lose
/// the key with a green report — the one-token mistake the crate's docs call
/// out, pinned here from the correct side.
#[test]
fn a_failed_import_is_incomplete_not_clean() {
    let s = scenarios()
        .into_iter()
        .find(|s| s.name == "a_failed_write_on_the_newest_predecessor")
        .expect("scenario");
    let (node, run) = run_scenario(&s);
    let classes: Vec<&str> = run
        .report
        .predecessors
        .iter()
        .map(|p| match p {
            PredecessorMigration::Incomplete { .. } => "Incomplete",
            PredecessorMigration::Imported { .. } => "Imported",
            other => panic!("unexpected classification {other:?}"),
        })
        .collect();
    assert_eq!(
        classes,
        vec!["Incomplete", "Imported"],
        "the failing newest predecessor is Incomplete and the walk continues"
    );
    assert_eq!(run.outcome.failed_imports, 1);
    assert_eq!(run.outcome.recovered, 1);
    assert_eq!(
        node.ns.borrow().visible(),
        BTreeSet::from(["fpGood".to_string()])
    );
}

// ===========================================================================
// The deliberate divergences, pinned so they stay decisions
// ===========================================================================

/// The one residual store difference: for a multi-generation recovery the
/// index lists the same fingerprints in walk order, and the walk direction
/// differs (sweep: oldest-first append; crate: newest-first). Everything else
/// in the store is byte-identical. Listing order in the vault UI follows the
/// index, so recovered keys can appear in a different order after the
/// adoption — cosmetic, and accepted (Ian, 2026-08-11), but it must stay a
/// decision, not a surprise.
#[test]
fn the_only_residual_store_difference_is_index_order() {
    let s = scenarios()
        .into_iter()
        .find(|s| s.name == "multiple_generations_newest_already_has_the_data")
        .expect("scenario");
    let rec = recorded(s.name);
    let (node, _run) = run_scenario(&s);

    let oracle_index: Vec<String> = {
        let store: BTreeMap<Vec<u8>, Vec<u8>> = rec
            .ghostkeys_store
            .iter()
            .map(|(k, v)| (unhex(k), unhex(v)))
            .collect();
        ghostkey_common::from_cbor(store.get(INDEX_KEY).expect("oracle index")).expect("cbor")
    };
    let adapter_index: Vec<String> = node.ns.borrow().index();
    assert_eq!(oracle_index, vec!["fpOld".to_string(), "fpNew".to_string()]);
    assert_eq!(
        adapter_index,
        vec!["fpNew".to_string(), "fpOld".to_string()]
    );
}

/// A fingerprint present in TWO generations with different labels: the crate
/// walks newest-first and the writer's per-run tracker declines the older
/// copy, so the NEWEST generation's certificate, signing key, and label win —
/// and the older generation is imported exactly zero times.
///
/// The shipped sweep, walking oldest-first, would have imported the older
/// copy first (restoring the OLD label) and then healed over it with the
/// newer cert+sk while leaving the old label in place. Newest-wins is the
/// accepted direction for the recovered label (Ian, 2026-08-11); this test is
/// what makes that divergence observable rather than latent.
#[test]
fn a_shared_fingerprint_takes_the_newest_generations_label() {
    let entries = legacy_entries();
    // Both generations' certificates derive the SAME fingerprint (that is
    // what "shared fingerprint" means); their signing-key bytes and labels
    // differ so the winner is observable.
    let old_gen = Key {
        fp: "fpShared".into(),
        cert: format!("{CERT_PREFIX}fpShared"),
        sk: "-----BEGIN ED25519_SIGNING_KEY_V1-----OLD-BYTES".into(),
        label: Some("old-name".into()),
    };
    let new_gen = Key {
        fp: "fpShared".into(),
        cert: format!("{CERT_PREFIX}fpShared"),
        sk: "-----BEGIN ED25519_SIGNING_KEY_V1-----fpShared".into(),
        label: Some("new-name".into()),
    };

    let preds = vec![
        Predecessor {
            entry: entries[0],
            generation: 0,
            state: PredecessorState::HoldsAndExports(vec![old_gen.clone()]),
        },
        Predecessor {
            entry: entries[1],
            generation: 1,
            state: PredecessorState::HoldsAndExports(vec![new_gen.clone()]),
        },
    ];
    let node = MockNode::new(&preds, Namespace::default());
    let run = run_adapter(&node, &preds, Some(vec![]));

    assert_eq!(run.outcome.recovered, 1, "one identity, announced once");
    assert_eq!(
        *node.import_sends.borrow(),
        1,
        "the older generation's copy is declined by the per-run tracker, so exactly \
         one ImportGhostKey is sent"
    );
    let ns = node.ns.borrow();
    assert_eq!(
        ns.secrets.get(&sk_key("fpShared")),
        Some(&new_gen.sk.clone().into_bytes()),
        "the NEWEST generation's signing key is the one installed"
    );
    assert_eq!(
        ns.secrets.get(&label_key("fpShared")),
        Some(&b"new-name".to_vec()),
        "the NEWEST generation's label wins (the sweep would have kept `old-name`)"
    );
    assert_eq!(
        node.labels_set.borrow().as_slice(),
        &[("fpShared".to_string(), "new-name".to_string())],
        "exactly one SetLabel, from the newest generation"
    );
}

// ===========================================================================
// The label-write gates
// ===========================================================================

/// A delegate that echoes a DIFFERENT fingerprint than the export metadata
/// claimed must not get a label write: a mis-delivered reply would otherwise
/// write this key's label onto another key, durably, with no self-correction
/// (the next startup sees the key as already held and skips the label path).
#[test]
fn a_mismatched_fingerprint_echo_blocks_the_label_write() {
    let entries = legacy_entries();
    // Export metadata claims `fpMeta`; the certificate derives `fpReal`.
    let confused = Key {
        fp: "fpMeta".into(),
        cert: format!("{CERT_PREFIX}fpReal"),
        sk: "-----BEGIN ED25519_SIGNING_KEY_V1-----fpReal".into(),
        label: Some("my label".into()),
    };
    let preds = vec![Predecessor {
        entry: entries[0],
        generation: 0,
        state: PredecessorState::HoldsAndExports(vec![confused]),
    }];
    let node = MockNode::new(&preds, Namespace::default());
    let run = run_adapter(&node, &preds, Some(vec![]));

    assert_eq!(run.outcome.recovered, 1, "the key itself is recovered");
    assert!(
        node.labels_set.borrow().is_empty(),
        "no SetLabel may be sent when the delegate echoed a different fingerprint"
    );
    assert!(
        !node.ns.borrow().secrets.contains_key(&label_key("fpReal")),
        "no label lands under the echoed fingerprint either"
    );
}

/// When the current delegate could not be listed (`already_held = None`),
/// every key must be treated as already held: imports still run (healing is
/// idempotent and safe), but nothing is announced as recovered and no legacy
/// label overwrites a name the user may have chosen.
#[test]
fn an_untrusted_held_list_suppresses_announcements_and_labels() {
    let preds = predecessors(vec![PredecessorState::HoldsAndExports(vec![key(
        "fpA",
        Some("legacy name"),
    )])]);
    let node = MockNode::new(&preds, Namespace::default());
    let run = run_adapter(&node, &preds, None);

    assert_eq!(run.outcome.recovered, 0, "nothing announced");
    assert!(node.labels_set.borrow().is_empty(), "no label restored");
    assert_eq!(*node.import_sends.borrow(), 1, "the heal import still runs");
    assert_eq!(run.imported.len(), 1, "the UI list is still refreshed");
    assert!(
        node.ns.borrow().complete_pairs().contains("fpA"),
        "both halves landed"
    );
    assert!(
        node.defaults_set.borrow().is_empty(),
        "no default carry-over on a pass that announced nothing"
    );
}

// ===========================================================================
// Default-identity carry-over
// ===========================================================================

/// The first (oldest) predecessor whose default names a key we now hold wins,
/// and a default naming an unrecovered key is ignored — the containment check
/// that stops `SignWithDefault` from silently resolving to a different
/// identity.
#[test]
fn the_default_identity_is_carried_with_containment() {
    let entries = legacy_entries();
    let preds = vec![Predecessor {
        entry: entries[0],
        generation: 0,
        state: PredecessorState::HoldsAndExports(vec![key("fpA", None), key("fpB", None)]),
    }];
    let mut node = MockNode::new(&preds, Namespace::default());
    node.pred_defaults
        .insert(entries[0].delegate_key.to_vec(), Some("fpB".into()));
    let run = run_adapter(&node, &preds, Some(vec![]));
    assert_eq!(run.outcome.recovered, 2);
    assert_eq!(
        node.defaults_set.borrow().as_slice(),
        &["fpB".to_string()],
        "the predecessor's default is adopted"
    );

    // Containment: a default naming a key that did NOT come across is ignored.
    let mut node2 = MockNode::new(&preds, Namespace::default());
    node2
        .pred_defaults
        .insert(entries[0].delegate_key.to_vec(), Some("fpZ".into()));
    let _run2 = run_adapter(&node2, &preds, Some(vec![]));
    assert!(
        node2.defaults_set.borrow().is_empty(),
        "a default naming an unrecovered key must be ignored"
    );
}

/// The adapter's probe mapping, pinned per reply kind. `probe_executable`
/// and `fetch_secrets` are LAYERED defences (the crate never fetches after a
/// false probe, and the fetch re-derives the decision from the cached
/// verdict), so a mutation to either alone is absorbed by the other — this
/// pins the probe half directly, and the export-send tests above pin the
/// end-to-end property.
#[test]
fn the_probe_answers_false_for_every_no_answer_verdict() {
    use crate::migration_adapter::GkPredecessorIo;
    use freenet_migrate::PredecessorSecretsIo;

    let cases = [
        (PredecessorState::Silent, false),
        (PredecessorState::NotRegistered, false),
        (PredecessorState::TransportFailure("socket closed"), false),
        (PredecessorState::RegisteredButEmpty, true),
        (
            PredecessorState::HoldsAndExports(vec![key("fpA", None)]),
            true,
        ),
        // Too old to know the question, answers with an error: executable.
        (
            PredecessorState::TooOldButExports(vec![key("fpA", None)]),
            true,
        ),
        // A delegate-level failure IS an answer.
        (PredecessorState::AnswersWithError("missing secret"), true),
    ];
    for (state, expected) in cases {
        let preds = predecessors(vec![state.clone()]);
        let node = MockNode::new(&preds, Namespace::default());
        let mut reader = GkPredecessorIo::new(&node);
        let target = DelegateKey::new(
            preds[0].entry.delegate_key,
            CodeHash::new(preds[0].entry.code_hash),
        );
        let got = block_on(reader.probe_executable(&target)).expect("probe never aborts");
        assert_eq!(
            got, expected,
            "probe_executable({state:?}) must answer {expected}"
        );
    }
}

/// A TRANSPORT-level import failure (the round-trip to the current delegate
/// times out) is a retryable failure, never a clean skip: the predecessor
/// must classify `Incomplete` with the item counted failed, so a retry
/// re-offers the key. Mapping this arm onto `AlreadyAuthoritative` is the
/// same one-token mistake as the answered-error arm, one line lower.
#[test]
fn a_transport_failed_import_is_incomplete_not_clean() {
    let entries = legacy_entries();
    let preds = vec![Predecessor {
        entry: entries[0],
        generation: 0,
        state: PredecessorState::HoldsAndExports(vec![key("fpLost", None)]),
    }];
    let mut node = MockNode::new(&preds, Namespace::default());
    node.import_transport_fail.insert("fpLost".into());
    let run = run_adapter(&node, &preds, Some(vec![]));

    match &run.report.predecessors[0] {
        PredecessorMigration::Incomplete { tally, .. } => {
            assert_eq!(tally.failed, 1, "the lost import is counted failed");
            assert_eq!(tally.written, 0);
            assert_eq!(tally.skipped, 0, "and NOT counted as a clean skip");
        }
        other => panic!("expected Incomplete, got {other:?}"),
    }
    assert_eq!(run.outcome.failed_imports, 1);
    assert!(
        node.ns.borrow().visible().is_empty(),
        "nothing landed, and the report must say so"
    );
}
