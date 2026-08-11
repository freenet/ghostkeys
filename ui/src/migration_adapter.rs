//! The `freenet-migrate` 0.5.0 adapter: ghostkeys' recovery sweep, driven by
//! the shared crate instead of the hand-rolled walk.
//!
//! # What moved and what stayed
//!
//! The crate now owns the WALK — which predecessors, newest-first, the
//! executability preflight, marker bookkeeping, per-predecessor
//! classification, cross-generation selection ([`SecretSelectionPolicy`]).
//! Ghostkeys keeps every app-specific judgement, deliberately hand-rolled
//! because `PredecessorMigration` cannot express the vault's four-way user
//! messaging:
//!
//! * the presence/probe CLASSIFICATION (`migration::classify_presence`,
//!   `migration::classify`, `migration::sweep_step`) — the decisions that can
//!   lose keys, unchanged and still pinned by `migration.rs`'s tests;
//! * the [`MigrationOutcome`] counters and their rendering
//!   (`migration::user_message`, `real::report`) — fed from this adapter's
//!   side-band observations rather than from the crate's report;
//! * `known_held` suppression (a listing failure must not let the sweep
//!   announce recoveries or overwrite user-chosen labels);
//! * the default-identity carry-over, including its containment check
//!   ([`migration::default_to_adopt`]).
//!
//! The adapter observing its own IO (recording a `PresenceVerdict` per
//! predecessor while answering the crate's narrower `Ok(bool)`) is the
//! supported pattern, not a fork: the crate's docs say the app owns transport
//! and classification of its own delegate protocol.
//!
//! # This is a UI-side adoption — the delegate WASM does NOT change
//!
//! Nothing here is reachable from `delegates/ghostkey-delegate`. The delegate
//! WASM must remain byte-identical to the PR-A baseline
//! (`0d0e2043c5242953b6e8705179ca6847f1d83fce8e23a4ae314118d9b22ffd62`), so
//! that the stdlib bump and this adoption cross ONE re-key together; the pin
//! test in `migration_registry_pin.rs` enforces it.
//!
//! # freenet-migrate#19 override, stated plainly
//!
//! The crate's recommended semantics treat a fetch timeout as clean
//! `Unresponsive { error: None }`, and an adapter could go further and report
//! silence as an empty export. This adapter NEVER returns `Ok(vec![])` for
//! silence: a predecessor that answered `HasIdentity` with "I hold keys" and
//! then never answered the export is positive evidence of stranded keys
//! (`present_but_silent`), and collapsing it into "no data" is the data-loss
//! default both 2026-08 adopters overrode. `fetch_secrets` returns `Err` for
//! timeout, transport failure, AND answered errors; only a genuine
//! `ExportAllResult` (possibly empty) or a confirmed-empty presence answer
//! produces `Ok`.
//!
//! # Markers are page-lifetime. A durable marker store is BANNED.
//!
//! `migration_marker` answers from an in-memory map that is created fresh for
//! every run, so every fresh page load re-sweeps the whole table — ghostkeys'
//! documented doctrine (`ui/src/migration.rs`, "Why there is no migration
//! done flag": no available signal can justify sealing a predecessor, because
//! `ExportAllGhostKeys` silently skips keys the caller lacks `Export` scope
//! on and the reply carries no count).
//!
//! Do NOT introduce a durable `MigrationMarkerStore` here (browser storage,
//! the delegate's secret store, anywhere). The 2026-08-11 re-measurement proved
//! with a contrast test that a durable marker resurrects the ghostkeys#32 D4
//! failure verbatim: a predecessor sealed `Done { had_data: false }` on one
//! pass hides keys that become exportable later, permanently and silently.
//! `migration_adapter_differential.rs` pins the page-lifetime behaviour.
//!
//! # Known, deliberate divergences from the outgoing hand-rolled sweep
//!
//! Measured by the differential suite; accepted by Ian (2026-08-11):
//!
//! * **`gk:index` order.** The sweep walked oldest-first and appended; the
//!   crate walks newest-first. Same membership, different listing order on a
//!   multi-generation recovery. Pinned as a known divergence.
//! * **Label newest-wins.** A fingerprint present in several generations with
//!   different labels now gets the NEWEST generation's label (the crate walks
//!   newest-first and this writer declines a fingerprint it already imported
//!   this run); the sweep's oldest-first walk restored the oldest. Pinned by
//!   `a_shared_fingerprint_takes_the_newest_generations_label`.
//! * **Withheld keys.** If the newest generation's copy of a fingerprint
//!   fails RETRYABLY, the crate withholds that same secret key from older
//!   generations for the rest of the run (so an older copy cannot shadow a
//!   newer one awaiting retry); the sweep would have tried the older copy
//!   immediately. The sweep re-runs on the next page load anyway, so the
//!   older copy is only deferred, never lost.
//!
//! The `UnionAllGenerations` policy re-imports keys deleted on a newer
//! generation. That is behaviour-preserving, not a regression: the shipped
//! sweep already re-imports every exportable legacy key on every startup, and
//! ghostkeys has no deletion tombstones for the sweep to honour.

use std::collections::{BTreeMap, BTreeSet};

use dioxus::logger::tracing::{info, warn};
use freenet_migrate::{
    migrate_delegate_secrets, DelegateLineageEntry, DelegateMigrationReport, ItemWrite,
    MarkerQuery, MigrationAuthorization, MigrationMarker, PredecessorSecretsIo, RecoveredSecret,
    SecretPair, SecretSelectionPolicy, SuccessorSecretsIo, UnionAck,
};
use freenet_stdlib::prelude::{CodeHash, DelegateKey};
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

use crate::api::delegate::DelegateCallError;
use crate::migration::{
    classify, classify_presence, default_to_adopt, sweep_step, MigrationOutcome, PresenceVerdict,
    ProbeVerdict, SweepStep,
};

// Generated by ui/build.rs from legacy_delegates.toml, on every target — the
// registry pin tests and the differential need it natively, and the vault
// needs it on wasm.
include!(concat!(env!("OUT_DIR"), "/legacy_delegates.rs"));

/// Seconds to wait for a legacy delegate to answer a probe. See the rationale
/// on the identically-named constant this replaces in `migration.rs`'s
/// history: a delegate the node has answers in milliseconds, so this only
/// bounds the wait for one it does not have, and those never answer at all.
pub(crate) const LEGACY_PROBE_TIMEOUT_SECS: u64 = 3;

/// Seconds to wait for the export itself, once a predecessor has shown it
/// holds something. This CAN involve a human: delegates from entry 12 onward
/// require a fresh user confirmation before handing over private keys.
/// Shared with the current-delegate export path so the two cannot drift.
pub(crate) const LEGACY_EXPORT_TIMEOUT_SECS: u64 =
    crate::api::delegate::USER_CONFIRMATION_TIMEOUT_SECS;

/// Seconds for ordinary (non-prompting) calls to the current delegate —
/// `ImportGhostKey`, `SetLabel`, `SetDefaultKey`. Matches the deadline
/// `api::delegate::send_request` applies to non-export requests.
pub(crate) const DELEGATE_CALL_TIMEOUT_SECS: u64 = 10;

/// Key prefix for the synthetic one-pair-per-credential encoding
/// [`GkPredecessorIo::fetch_secrets`] hands the crate: `gkm:v1:<fingerprint>`,
/// value = CBOR of [`ghostkey_common::ExportedGhostKey`].
///
/// Deliberately NOT the delegate's own `gk:` namespace: these pairs exist
/// only in transit between the adapter's two halves. There is no `gk:index`
/// pair and no `gk:perms:` pair — the delegate's own `ImportGhostKey` handler
/// owns the index append and the permission grant, which is the entire point
/// of routing writes through it (ghostkeys#32 findings D3 and D9).
pub(crate) const CRED_KEY_PREFIX: &str = "gkm:v1:";

/// One request/response round-trip against a specific delegate, abstracted so
/// the whole adapter runs natively in unit tests. The wasm implementation is
/// [`NodeChannel`], which delegates to `api::delegate::send_to_delegate` (and
/// so inherits its FIFO reply correlation, per-key call lock, and
/// private-key delivery gate).
///
/// Takes `&self` deliberately: [`migrate_delegate_secrets`] holds the
/// predecessor reader and the successor writer as two simultaneous `&mut`
/// borrows and BOTH need the transport.
pub(crate) trait GkDelegateChannel {
    fn call(
        &self,
        target: &DelegateKey,
        request: GhostkeyRequest,
        timeout_secs: u64,
    ) -> impl std::future::Future<Output = Result<GhostkeyResponse, DelegateCallError>>;
}

/// The production channel: every round-trip goes through
/// `api::delegate::send_to_delegate`.
#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
pub(crate) struct NodeChannel;

#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
impl GkDelegateChannel for NodeChannel {
    async fn call(
        &self,
        target: &DelegateKey,
        request: GhostkeyRequest,
        timeout_secs: u64,
    ) -> Result<GhostkeyResponse, DelegateCallError> {
        crate::api::delegate::send_to_delegate(target, request, timeout_secs).await
    }
}

// ---------------------------------------------------------------------------
// Predecessor side
// ---------------------------------------------------------------------------

/// Reads predecessors through ghostkeys' own delegate protocol, recording the
/// full four-way [`PresenceVerdict`] per predecessor in a side-band the
/// crate's `Ok(bool)` cannot carry, so [`MigrationOutcome`]'s counters stay
/// exactly as expressive as the hand-rolled sweep's.
pub(crate) struct GkPredecessorIo<'a, C> {
    channel: &'a C,
    /// The presence verdict recorded by `probe_executable`, consulted by
    /// `fetch_secrets` for the same predecessor. Keyed by delegate-key bytes.
    presence: BTreeMap<Vec<u8>, PresenceVerdict>,
    /// Side-band probe/export counters, accumulated with the SAME shipped
    /// functions (`record_probe`) and in the same order as the outgoing
    /// sweep, so the user-facing report cannot drift.
    pub(crate) outcome: MigrationOutcome,
}

impl<'a, C: GkDelegateChannel> GkPredecessorIo<'a, C> {
    pub(crate) fn new(channel: &'a C) -> Self {
        Self {
            channel,
            presence: BTreeMap::new(),
            outcome: MigrationOutcome::default(),
        }
    }
}

impl<C: GkDelegateChannel> PredecessorSecretsIo for GkPredecessorIo<'_, C> {
    type Error = String;

    /// `HasIdentity` with the short probe deadline. It never prompts, by
    /// construction, so no private-key dialog can fire here.
    ///
    /// `Ok(false)` covers `NotRegistered` AND timeout AND local transport
    /// failure — everything `classify_presence` files as `NoAnswer`. None of
    /// them aborts the walk and none reaches the 90s export deadline, so an
    /// absent predecessor costs one 3s probe, exactly as before. `Ok(true)`
    /// is ANY answer, including `Unsettled` (a delegate too old to know the
    /// question has still proved it executes) — treating `Unsettled` as
    /// non-executable would strand every key held by the oldest half of the
    /// table.
    async fn probe_executable(&mut self, predecessor: &DelegateKey) -> Result<bool, String> {
        let verdict = classify_presence(
            self.channel
                .call(
                    predecessor,
                    GhostkeyRequest::HasIdentity,
                    LEGACY_PROBE_TIMEOUT_SECS,
                )
                .await,
        );
        let executable = !matches!(verdict, PresenceVerdict::NoAnswer(_));
        if let PresenceVerdict::NoAnswer(probe) = &verdict {
            // The sweep's own bookkeeping for a predecessor that never spoke:
            // counted (undetermined / not_registered), never user-facing.
            self.outcome.record_probe(probe, false);
            match probe {
                ProbeVerdict::Undetermined(reason) => info!(
                    "Legacy delegate {} did not answer ({reason})",
                    predecessor.encode()
                ),
                ProbeVerdict::Skipped => info!(
                    "Legacy delegate {} is not registered on this node",
                    predecessor.encode()
                ),
                _ => {}
            }
        }
        self.presence.insert(predecessor.bytes().to_vec(), verdict);
        Ok(executable)
    }

    /// Ask for the keys — but only when the presence answer warrants it.
    ///
    /// A predecessor that answered "I hold nothing" is skipped WITHOUT
    /// sending `ExportAllGhostKeys` (`Ok(vec![])` directly): delegates from
    /// entry 12 onward raise a private-key confirmation dialog on export, and
    /// older delegates may prompt unconditionally, so probing an empty
    /// predecessor would put an unexplained dialog in front of the user on
    /// every vault open. This never-prompt-an-empty-predecessor rule must
    /// survive every future edit.
    ///
    /// Silence is NEVER `Ok(vec![])` — see the module docs (#19 override).
    async fn fetch_secrets(
        &mut self,
        predecessor: &DelegateKey,
    ) -> Result<Vec<SecretPair>, String> {
        let Some(presence) = self.presence.get(predecessor.bytes()) else {
            // The crate always probes before fetching; reaching this is a
            // driver bug, and guessing "empty" would be the exact data-loss
            // default this adapter exists to override.
            return Err("fetch_secrets called before probe_executable".into());
        };
        let had_presence = match sweep_step(presence) {
            SweepStep::Skip => return Ok(Vec::new()),
            // `probe_executable` answered false for every NoAnswer verdict,
            // so the crate never fetches those.
            SweepStep::Record => return Err("predecessor did not answer the probe".into()),
            SweepStep::Export { had_presence } => had_presence,
        };

        let verdict = classify(
            self.channel
                .call(
                    predecessor,
                    GhostkeyRequest::ExportAllGhostKeys,
                    LEGACY_EXPORT_TIMEOUT_SECS,
                )
                .await,
        );
        // Same bookkeeping call, same `had_presence` flag, as the sweep: an
        // empty export from a delegate that claimed keys files
        // present_but_unexportable; silence after a presence claim files
        // present_but_silent; an answered failure files answered_with_error.
        self.outcome.record_probe(&verdict, had_presence);

        match verdict {
            ProbeVerdict::Exported(keys) => keys
                .into_iter()
                .map(|k| {
                    let pair_key = format!("{CRED_KEY_PREFIX}{}", k.fingerprint).into_bytes();
                    ghostkey_common::to_cbor(&k)
                        .map(|value| (pair_key, value))
                        .map_err(|e| format!("encode exported key: {e}"))
                })
                .collect(),
            ProbeVerdict::Skipped => {
                info!(
                    "Legacy delegate {} vanished between probe and export",
                    predecessor.encode()
                );
                Err("delegate is not registered on this node".into())
            }
            ProbeVerdict::Undetermined(reason) => {
                info!(
                    "Legacy delegate {} did not answer the export ({reason})",
                    predecessor.encode()
                );
                Err(format!("no export reply: {reason}"))
            }
            ProbeVerdict::AnsweredWithError(reason) => {
                warn!(
                    "Legacy delegate {} answered the export with an error: {reason}",
                    predecessor.encode()
                );
                Err(format!("export failed: {reason}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Successor side
// ---------------------------------------------------------------------------

/// Whether the current delegate's refusal of an `ImportGhostKey` is stable
/// across time, i.e. safe to report as [`freenet_migrate::RetryAdvice::Permanent`].
///
/// The strings are the CURRENT delegate's own frozen answers
/// (`delegates/ghostkey-delegate/src/handlers.rs::handle_import`) — frozen
/// because the deployed WASM cannot change without the re-key this whole
/// module exists to survive, and the successor ships in the same bundle as
/// this adapter. All four name a property of the key material itself (a PEM
/// that does not parse, a chain that does not verify against the compiled-in
/// master key, a signing key that does not match its certificate), which no
/// re-run can change. Everything else — the grant-write failure, a serialize
/// failure, an unrecognized wording — is reported retryable: when in doubt,
/// `retryable` costs a re-walk, not the data.
pub(crate) fn import_refusal_is_permanent(message: &str) -> bool {
    message.starts_with("invalid certificate PEM")
        || message.starts_with("certificate verification failed")
        || message.starts_with("invalid signing key PEM")
        || message.starts_with("signing key does not match certificate")
}

/// Ghostkeys' own import path, as the crate's successor writer: every
/// recovered credential goes through the current delegate's `ImportGhostKey`
/// handler, which verifies the certificate chain, derives the fingerprint,
/// appends the index, and records the vault's permission grant — the four
/// things a raw pair copy skips (ghostkeys#32).
pub(crate) struct GkSuccessorIo<'a, C, F> {
    channel: &'a C,
    current: DelegateKey,
    /// Fingerprints the current delegate already lists. Grows as imports
    /// succeed, so a fingerprint exported by two generations is announced at
    /// most once.
    held: BTreeSet<String>,
    /// Whether `held` is trustworthy. When the current delegate could not be
    /// listed, every key looks new: announcing recoveries and restoring
    /// legacy labels would overwrite the user's chosen names, so both are
    /// suppressed (`already_held` is then true for everything).
    known_held: bool,
    /// Fingerprints imported by THIS run. The newest generation is walked
    /// first, so declining a repeat here is what makes the newest
    /// generation's copy (and label) win a shared fingerprint — the ONLY
    /// mechanism enforcing Union's newest-wins guarantee (the crate cannot
    /// read the successor). Do not remove.
    imported_this_run: BTreeSet<String>,
    /// Which predecessor supplied which fingerprints (echoed by the
    /// delegate), oldest-first by generation, for the default-identity
    /// carry-over.
    recovered_from: Vec<(u32, DelegateKey, BTreeSet<String>)>,
    /// Import bookkeeping, accumulated with the SAME shipped
    /// `MigrationOutcome::record_import` the hand-rolled sweep used (only the
    /// `recovered` / `failed_imports` counters are populated here; the probe
    /// counters live in [`GkPredecessorIo`]).
    imports: MigrationOutcome,
    /// Page-lifetime markers: an in-memory map, created fresh with this
    /// writer, discarded with it. `migration_marker` therefore answers
    /// `Ok(None)` for every predecessor on every fresh page load, so the
    /// sweep runs every startup. Do NOT replace this with durable storage —
    /// see the module docs (the D4 sealed-empty failure).
    markers: BTreeMap<Vec<u8>, MigrationMarker>,
    /// UI hook: called for every successful import (including a heal of an
    /// already-listed key), exactly where the sweep called
    /// `ghostkey_list::add_ghostkey`.
    on_imported: F,
}

impl<'a, C: GkDelegateChannel, F: FnMut(GhostKeyInfo)> GkSuccessorIo<'a, C, F> {
    pub(crate) fn new(
        channel: &'a C,
        current: DelegateKey,
        already_held: Option<Vec<String>>,
        on_imported: F,
    ) -> Self {
        let known_held = already_held.is_some();
        Self {
            channel,
            current,
            held: already_held.unwrap_or_default().into_iter().collect(),
            known_held,
            imported_this_run: BTreeSet::new(),
            recovered_from: Vec::new(),
            imports: MigrationOutcome::default(),
            markers: BTreeMap::new(),
            on_imported,
        }
    }

    fn record_source(&mut self, generation: u32, predecessor: &DelegateKey, fingerprint: &str) {
        if let Some((_, _, set)) = self
            .recovered_from
            .iter_mut()
            .find(|(_, key, _)| key == predecessor)
        {
            set.insert(fingerprint.to_string());
        } else {
            self.recovered_from.push((
                generation,
                predecessor.clone(),
                BTreeSet::from([fingerprint.to_string()]),
            ));
        }
    }
}

impl<C: GkDelegateChannel, F: FnMut(GhostKeyInfo)> SuccessorSecretsIo for GkSuccessorIo<'_, C, F> {
    type Error = String;

    async fn migration_marker(
        &mut self,
        query: &MarkerQuery<'_>,
    ) -> Result<Option<MigrationMarker>, String> {
        // In-memory only: `None` for everything at the start of a run, which
        // is what makes the sweep run on every page load. The map exists so
        // the crate's WITHIN-run marker discipline still works (a predecessor
        // is never walked twice in one run).
        Ok(self.markers.get(query.predecessor.bytes()).copied())
    }

    async fn record_marker(
        &mut self,
        predecessor: &DelegateKey,
        marker: MigrationMarker,
    ) -> Result<(), String> {
        self.markers.insert(predecessor.bytes().to_vec(), marker);
        Ok(())
    }

    /// The seam the whole adoption exists for: decode the credential, route
    /// it through the delegate's own `ImportGhostKey`, and only label it when
    /// the delegate's echoed fingerprint proves the reply is about this key.
    async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<String> {
        let Some(fp) = std::str::from_utf8(item.key)
            .ok()
            .and_then(|s| s.strip_prefix(CRED_KEY_PREFIX))
            .map(str::to_string)
        else {
            // Unreachable today — `fetch_secrets` only emits `gkm:v1:` pairs —
            // but if a future fetch encoding ever adds a second pair kind, a
            // real user's key could ride in it. Sealing an unknown item as
            // "already authoritative" would silently drop that key with a
            // clean report (the ghostkeys#32 D3/D9 shape, through the writer
            // instead of the copier), so an unrecognized key is a PERMANENT
            // failure that names the mismatch: it will not become
            // recognizable on a retry, and it must surface loudly instead of
            // accumulating retries. Pinned by
            // `an_unrecognized_pair_key_is_a_permanent_failure_not_a_clean_skip`.
            return ItemWrite::permanent(format!(
                "unrecognized pair key (adapter/fetch encoding mismatch): {:?}",
                String::from_utf8_lossy(item.key)
            ));
        };
        let key: ghostkey_common::ExportedGhostKey = match ghostkey_common::from_cbor(item.value) {
            Ok(k) => k,
            // Bytes this adapter itself encoded; failing to decode them will
            // not improve on a retry.
            Err(e) => return ItemWrite::permanent(format!("decode recovered credential: {e}")),
        };

        if self.imported_this_run.contains(&fp) {
            // A NEWER generation already supplied this credential in this
            // run. Declining here is what makes newest-wins hold under
            // Union — see the field docs on `imported_this_run`.
            return ItemWrite::already_authoritative();
        }

        // Import even a fingerprint the current delegate already lists.
        // `ListGhostKeys` reports a key whenever its CERTIFICATE loads and
        // never checks the signing key, so a key whose cert survived but
        // whose signing key did not looks present, cannot sign, and skipping
        // it would strand it in that state forever. Re-importing overwrites
        // both halves and heals it; `handle_import` is idempotent.
        //
        // What must NOT repeat is the announcing: counting it as a recovery,
        // or restoring the legacy label over a name the user has since
        // chosen.
        let already_held = !self.known_held || self.held.contains(&fp);

        match self
            .channel
            .call(
                &self.current,
                GhostkeyRequest::ImportGhostKey {
                    certificate_pem: key.certificate_pem.clone(),
                    signing_key_pem: key.signing_key_pem.clone(),
                },
                DELEGATE_CALL_TIMEOUT_SECS,
            )
            .await
        {
            Ok(GhostkeyResponse::ImportResult {
                fingerprint,
                notary_info,
            }) => {
                self.imported_this_run.insert(fp);
                self.held.insert(fingerprint.clone());
                self.record_source(item.generation, item.predecessor, &fingerprint);
                (self.on_imported)(GhostKeyInfo {
                    fingerprint: fingerprint.clone(),
                    label: key.label.clone(),
                    notary_info,
                    verifying_key_bytes: None,
                    // The backup marker lives in the delegate's own secret
                    // namespace, which a re-key moves, so a recovered key
                    // always starts un-marked. Over-warns rather than
                    // under-warns, which is the direction to err in when the
                    // cost is the key.
                    backed_up: false,
                });

                if !already_held {
                    info!("Recovered ghostkey {fingerprint}");
                    self.imports.record_import(true);

                    if let Some(label) = &key.label {
                        // Only label the key we actually asked to import. The
                        // delegate echoes the fingerprint it derived from the
                        // certificate; a mis-delivered reply (see
                        // `api::delegate::claim_waiter`) would otherwise write
                        // THIS key's label onto ANOTHER key — a durable write
                        // that does not self-correct, because the next startup
                        // sees that key as already held and skips this path.
                        // On a mismatch the safe action is to skip a cosmetic
                        // write, not to guess a target for it.
                        if fingerprint == key.fingerprint {
                            let _ = self
                                .channel
                                .call(
                                    &self.current,
                                    GhostkeyRequest::SetLabel {
                                        fingerprint,
                                        label: label.clone(),
                                    },
                                    DELEGATE_CALL_TIMEOUT_SECS,
                                )
                                .await;
                        } else {
                            warn!(
                                "Not labelling {}: delegate echoed a different fingerprint \
                                 ({fingerprint})",
                                key.fingerprint
                            );
                        }
                    }
                }
                ItemWrite::written()
            }
            // The key is still only in the predecessor. Counting it as
            // recovered — or, worse, answering `AlreadyAuthoritative`, which
            // seals the predecessor clean and never re-offers the key — would
            // report a success that did not happen. A failed write is
            // `retryable` or `permanent`, NEVER `AlreadyAuthoritative`.
            Ok(other) => {
                let kind = crate::api::delegate::response_kind(&other);
                warn!("Could not re-import {}: {kind}", key.fingerprint);
                // Only a failure to bring over a key we do NOT already have is
                // worth reporting; a failed refresh of one we already hold
                // leaves the user no worse off.
                if !already_held {
                    self.imports.record_import(false);
                }
                if let GhostkeyResponse::Error { message } = &other {
                    if import_refusal_is_permanent(message) {
                        return ItemWrite::permanent(format!("import refused: {message}"));
                    }
                    return ItemWrite::retryable(format!("import failed: {message}"));
                }
                ItemWrite::retryable(format!("unexpected import reply: {kind}"))
            }
            Err(e) => {
                warn!("Could not re-import {}: {e}", key.fingerprint);
                if !already_held {
                    self.imports.record_import(false);
                }
                ItemWrite::retryable(format!("import round-trip failed: {e}"))
            }
        }
    }

    /// No-op, honestly: every write above awaited the delegate's own
    /// acknowledgement before answering `Written` (write-through, never
    /// buffered), so there is nothing left to flush.
    async fn flush_predecessor(&mut self, _predecessor: &DelegateKey) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// The policy ghostkeys migrates under: [`SecretSelectionPolicy::UnionAllGenerations`].
///
/// `NewestSnapshotWins` halts the walk at the first silent predecessor, and
/// silence is the ORDINARY case here — measured on a live node, nine legacy
/// entries produced nine timeouts, because a node that never ran a given
/// vault version does not answer probes for its delegate at all. Halting
/// there would strand every older generation's keys.
///
/// The [`UnionAck`] acknowledges union's two hazards. Resurrection of
/// deleted-by-absence secrets is behaviour-preserving for ghostkeys: the
/// shipped sweep already re-imports every exportable legacy key on every
/// startup, with no tombstones to honour. Run-scoped withholding
/// (freenet-migrate#15) is noted in the module docs.
pub(crate) fn gk_secret_policy() -> SecretSelectionPolicy {
    SecretSelectionPolicy::UnionAllGenerations(
        UnionAck::i_understand_union_resurrects_deleted_by_absence_secrets(),
    )
}

/// Build the crate's lineage from the generated `LEGACY_DELEGATES` table.
///
/// The table is `(delegate_key, code_hash)` in file order, oldest first, so
/// the index is the generation — the registry has no generation column, and
/// file order is the only ordering available (two rows are known to record a
/// local and a CI build of the SAME change, so treat generations as walk
/// order, not history). The entry matching the CURRENT delegate is skipped,
/// exactly as the sweep skipped it: the current key is recorded on main at
/// publish time, so the tail entry usually IS the running delegate.
///
/// `irregular_key: false` for every row: `ui/build.rs` now validates
/// `delegate_key == BLAKE3(code_hash)` at build time, so no row is trusted
/// as-recorded.
pub(crate) fn lineage_from_table(
    table: &[([u8; 32], [u8; 32])],
    current: &DelegateKey,
) -> Vec<DelegateLineageEntry> {
    table
        .iter()
        .enumerate()
        .filter_map(|(generation, (delegate_key, code_hash))| {
            let key = DelegateKey::new(*delegate_key, CodeHash::new(*code_hash));
            if key == *current {
                return None;
            }
            Some(DelegateLineageEntry {
                generation: generation as u32,
                code_hash: *code_hash,
                delegate_key: *delegate_key,
                irregular_key: false,
                note: "ghostkeys legacy delegate",
            })
        })
        .collect()
}

/// One crate-driven pass over the legacy delegate table.
///
/// Returns the [`MigrationOutcome`] for the user-facing report (fed from the
/// adapter's side-band, not from the crate's classification) and the crate's
/// own [`DelegateMigrationReport`] for logging and tests.
pub(crate) async fn run_crate_migration<C: GkDelegateChannel>(
    channel: &C,
    current: &DelegateKey,
    table: &[([u8; 32], [u8; 32])],
    already_held: Option<Vec<String>>,
    on_imported: impl FnMut(GhostKeyInfo),
) -> (MigrationOutcome, DelegateMigrationReport) {
    let lineage = lineage_from_table(table, current);
    let mut reader = GkPredecessorIo::new(channel);
    let mut writer = GkSuccessorIo::new(channel, current.clone(), already_held, on_imported);

    let report = migrate_delegate_secrets(
        &mut writer,
        &mut reader,
        &lineage,
        MigrationAuthorization::app_author_ack(),
        gk_secret_policy(),
    )
    .await;

    let mut outcome = reader.outcome;
    outcome.recovered = writer.imports.recovered;
    outcome.failed_imports = writer.imports.failed_imports;

    // The default-identity choice lives in the predecessor's secret
    // namespace, so a re-key loses it and `resolve_default` silently falls
    // back to the highest-tier key. `SignWithDefault` would then sign as a
    // DIFFERENT identity than before the update, with no prompt. Carry it
    // over — but only when this pass actually recovered something, which
    // makes it a once-per-migration event rather than something that fights
    // a choice the user makes later.
    if outcome.recovered > 0 {
        // Oldest-first, preserving the outgoing sweep's walk order for the
        // "first answer naming a key we now hold wins" rule. (The crate
        // walked newest-first; re-sorting here keeps the carry-over's
        // behaviour identical to what shipped.)
        let mut sources = writer.recovered_from;
        sources.sort_by_key(|(generation, _, _)| *generation);
        carry_default_identity(channel, current, &sources).await;
    }

    (outcome, report)
}

/// Ask each predecessor that supplied keys which identity it treated as the
/// default, and adopt the first answer naming a key we now hold.
///
/// The containment check inside [`default_to_adopt`] is the point: adopting a
/// default that names a key this vault does not hold would leave
/// `SignWithDefault` resolving to nothing or, worse, silently falling back to
/// a different identity — the failure the carry-across exists to prevent,
/// reintroduced from the other side.
async fn carry_default_identity<C: GkDelegateChannel>(
    channel: &C,
    current: &DelegateKey,
    sources: &[(u32, DelegateKey, BTreeSet<String>)],
) {
    let mut answers: Vec<(Option<String>, BTreeSet<String>)> = Vec::new();
    for (_, legacy_key, recovered) in sources {
        let answer = match channel
            .call(
                legacy_key,
                GhostkeyRequest::GetDefaultKey,
                LEGACY_PROBE_TIMEOUT_SECS,
            )
            .await
        {
            Ok(GhostkeyResponse::DefaultKeyResult { fingerprint }) => fingerprint,
            _ => None,
        };
        answers.push((answer, recovered.clone()));
    }
    let Some(fp) = default_to_adopt(&answers) else {
        return;
    };
    match channel
        .call(
            current,
            GhostkeyRequest::SetDefaultKey {
                fingerprint: fp.clone(),
            },
            DELEGATE_CALL_TIMEOUT_SECS,
        )
        .await
    {
        Ok(GhostkeyResponse::DefaultKeySet { .. }) => {
            info!("Carried the default identity {fp} across the update")
        }
        Ok(other) => warn!(
            "Could not carry the default identity across: {}",
            crate::api::delegate::response_kind(&other)
        ),
        Err(e) => warn!("Could not carry the default identity across: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The permanent set is exactly the delegate's four stable refusals of
    /// the key material itself. Everything else must stay retryable —
    /// `Permanent` is not withheld from older generations and seals a clean
    /// predecessor forever under never-clobber, so an over-broad match here
    /// silently gives up on recoverable keys.
    #[test]
    fn only_stable_refusals_are_permanent() {
        for msg in [
            "invalid certificate PEM: bad armor",
            "certificate verification failed: unknown authority",
            "invalid signing key PEM: truncated",
            "signing key does not match certificate's verifying key",
        ] {
            assert!(import_refusal_is_permanent(msg), "{msg} is stable");
        }
        for msg in [
            "imported the ghostkey but could not record ownership of it",
            "serialize certificate: out of memory",
            "some wording a future delegate might use",
            "",
        ] {
            assert!(!import_refusal_is_permanent(msg), "{msg} must be retryable");
        }
    }

    /// The generated registry table is what the vault sweeps; it must be
    /// non-empty and the lineage builder must skip exactly the current key.
    #[test]
    fn lineage_skips_only_the_current_key() {
        assert!(!LEGACY_DELEGATES.is_empty());
        let (dk, ch) = LEGACY_DELEGATES[LEGACY_DELEGATES.len() - 1];
        let current = DelegateKey::new(dk, CodeHash::new(ch));
        let lineage = lineage_from_table(LEGACY_DELEGATES, &current);
        assert_eq!(lineage.len(), LEGACY_DELEGATES.len() - 1);
        assert!(lineage.iter().all(|e| e.delegate_key != dk));

        let foreign = DelegateKey::new([0xCCu8; 32], CodeHash::new([0xCCu8; 32]));
        assert_eq!(
            lineage_from_table(LEGACY_DELEGATES, &foreign).len(),
            LEGACY_DELEGATES.len(),
            "a current key not in the table skips nothing"
        );
    }

    /// The default-identity carry-across is WIRED IN, gated on a pass that
    /// recovered something. Moved here from `migration.rs` (where it pinned
    /// the hand-rolled sweep's copy of the same wiring) when the walk moved
    /// into this adapter; the failure it guards is unchanged — the carry was
    /// once written, lost to a stray checkout, and compiled warning-free
    /// afterwards because leftover scaffolding still counted as a use.
    #[test]
    fn the_adapter_carries_the_default_identity_across() {
        // Only the code above the test module, so the needles below cannot
        // match themselves through `include_str!`.
        let src = include_str!("migration_adapter.rs");
        const TEST_MODULE_MARKER: &str = "#[cfg(test)]\nmod tests {";
        assert!(
            src.contains(TEST_MODULE_MARKER),
            "the test-module marker moved; this scrape would otherwise search the whole \
             file and match its own string literals"
        );
        let code = src.split(TEST_MODULE_MARKER).next().unwrap();

        // The CALL SITE, not just the symbol: a definition left behind while
        // the call is gone still contains every identifier.
        for needle in [
            "GhostkeyRequest::SetDefaultKey",
            "default_to_adopt(&answers)",
            "carry_default_identity(channel, current, &sources).await",
        ] {
            assert!(
                code.contains(needle),
                "the default-identity carry-across is not wired in: `{needle}` is missing"
            );
        }

        // The gate, anchored to the call it guards.
        let call = "carry_default_identity(channel, current, &sources).await";
        let call_at = code.find(call).expect("call site asserted above");
        let preceding = &code[call_at.saturating_sub(700)..call_at];
        assert!(
            preceding.contains("if outcome.recovered > 0 {"),
            "the carry-across must be gated on a pass that actually recovered something, \
             or it fights a choice the user makes later. Preceding source was: {preceding}"
        );
    }

    /// The adapter must keep calling the SAME shipped decision functions the
    /// hand-rolled sweep called, in the same order: presence classification,
    /// the sweep-step decision, export classification, outcome bookkeeping,
    /// and the delegate's own import handler. This is the successor of
    /// `migration_differential::the_harness_mirrors_the_shipped_sweep`, whose
    /// mirror target (`run_pass`) this adapter replaced.
    #[test]
    fn the_adapter_uses_the_shipped_decisions_in_order() {
        let src = include_str!("migration_adapter.rs");
        const TEST_MODULE_MARKER: &str = "#[cfg(test)]\nmod tests {";
        let code = src.split(TEST_MODULE_MARKER).next().unwrap();

        let mut at = 0usize;
        for needle in [
            "classify_presence(",
            "GhostkeyRequest::HasIdentity",
            "sweep_step(presence)",
            "GhostkeyRequest::ExportAllGhostKeys",
            "self.outcome.record_probe(&verdict, had_presence);",
            "GhostkeyRequest::ImportGhostKey",
            "GhostkeyRequest::SetLabel",
        ] {
            let found = code[at..].find(needle).unwrap_or_else(|| {
                panic!("the adapter no longer contains `{needle}` in the expected order")
            });
            at += found + needle.len();
        }
    }

    /// Markers must stay page-lifetime: no durable storage anywhere in this
    /// module. A durable marker store resurrects the ghostkeys#32 D4
    /// sealed-empty failure (proven by contrast test in the differential), so
    /// this pins the ABSENCE of the mechanisms one would be built from. The
    /// behavioural half of the pin is
    /// `migration_adapter_differential::a_fresh_run_reprobes_a_predecessor_sealed_empty_last_run`.
    #[test]
    fn markers_have_no_durable_home() {
        // Only the code above the test module: the forbidden tokens below
        // would otherwise match their own string literals.
        let src = include_str!("migration_adapter.rs");
        const TEST_MODULE_MARKER: &str = "#[cfg(test)]\nmod tests {";
        assert!(src.contains(TEST_MODULE_MARKER), "test-module marker moved");
        let code = src.split(TEST_MODULE_MARKER).next().unwrap();
        for forbidden in ["localStorage", "local_storage", "set_secret", "Storage"] {
            assert!(
                !code.contains(forbidden),
                "`{forbidden}` appeared in migration_adapter.rs — markers must be \
                 page-lifetime, never durable (D4)"
            );
        }
    }
}
