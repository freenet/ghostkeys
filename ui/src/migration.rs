//! Recovery of stored ghostkeys from previous delegate versions.
//!
//! Every change to the delegate WASM re-keys the delegate -- its key is
//! `BLAKE3(BLAKE3(wasm) || params)` -- which moves the secret namespace it
//! reads and writes. Secrets stored under a predecessor are not deleted, only
//! unreachable, so the vault sweeps `legacy_delegates.toml` on startup and
//! re-imports whatever it finds.
//!
//! On a hosted node this is the *only* safety net. freenet-core's own
//! predecessor copy-forward deliberately skips user-scope secrets (the
//! per-user DEK is not derivable at rest), so nothing else will carry a
//! hosted user's keys across a re-key.
//!
//! # Why there is no "migration done" flag
//!
//! There used to be one, in `localStorage`, and it never did anything: the
//! vault runs in the shell's iframe, which is sandboxed without
//! `allow-same-origin`, so its origin is opaque and every `localStorage`
//! access throws. Verified against a live node -- the app frame reports
//! `SecurityError: The document is sandboxed and lacks the 'allow-same-origin'
//! flag`, while the top-level shell reads and writes storage normally.
//!
//! It should not come back even if storage becomes available, because no
//! available signal would justify setting it. The obvious candidate -- "the
//! node says that delegate is not registered" -- is not proof of absence (see
//! `DelegateCallError::NotRegistered`), and neither is an empty export:
//! `ExportAllGhostKeys` silently skips any key the caller lacks `Export` scope
//! on, or whose material fails to decode, and the reply carries no count to
//! check against. A flag that permanently stops the vault looking, set on
//! evidence that cannot support it, is exactly how keys get stranded.
//!
//! Sweeping on every startup is therefore the behaviour, not a fallback --
//! and measured against a live node, it is also what already happens today,
//! since the flag never persisted.
//!
//! It is not free. A node that does not have a given legacy delegate does not
//! answer the probe *at all* -- verified by driving the published vault in a
//! browser: nine legacy entries, nine `Timeout waiting for delegate response`,
//! and no error response for any of them. So the sweep costs one full deadline
//! per absent entry. Two things keep that tolerable: it runs after the vault
//! has already loaded and rendered what the current delegate holds, so the
//! user is never waiting on it, and the deadline is sized for a local WASM
//! call rather than a network round trip.

/// What one pass over the legacy delegate table established. Reported to the
/// user; it does not gate anything.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MigrationOutcome {
    /// Keys recovered that the current delegate did not already hold.
    pub recovered: usize,
    /// Legacy delegates that gave no definite answer, so we do not know
    /// whether they hold keys.
    pub undetermined: usize,
    /// Keys a legacy delegate handed over that would not re-import.
    pub failed_imports: usize,
}

impl MigrationOutcome {
    /// Whether every legacy delegate answered and every key it offered was
    /// re-imported. Purely a reporting distinction -- the sweep runs again on
    /// the next startup either way.
    pub(crate) fn is_conclusive(&self) -> bool {
        self.undetermined == 0 && self.failed_imports == 0
    }

    /// Whether the user needs telling that something could not be checked.
    pub(crate) fn needs_user_attention(&self) -> bool {
        !self.is_conclusive()
    }

    pub(crate) fn record_probe(&mut self, verdict: &ProbeVerdict) {
        if matches!(verdict, ProbeVerdict::Undetermined(_)) {
            self.undetermined += 1;
        }
    }

    pub(crate) fn record_import(&mut self, recovered: bool) {
        if recovered {
            self.recovered += 1;
        } else {
            self.failed_imports += 1;
        }
    }
}

/// What a probe of one legacy delegate established.
///
/// No `PartialEq`: `ExportedGhostKey` carries key material and does not
/// implement it, and a derive here would invite comparing secrets by value.
#[derive(Debug, Clone)]
pub(crate) enum ProbeVerdict {
    /// The delegate answered with the keys it holds, possibly none.
    Exported(Vec<ghostkey_common::ExportedGhostKey>),
    /// Nothing actionable, and nothing to worry about right now. Notably NOT
    /// a claim that the delegate holds nothing -- see
    /// `DelegateCallError::NotRegistered`. Since the sweep seals nothing, a
    /// wrong read here costs one pass, not permanence.
    Skipped,
    /// No usable answer. The delegate may be holding keys we could not see,
    /// so the user is told rather than left with a silently partial sweep.
    Undetermined(String),
}

/// Decide what one probe reply means.
///
/// Split out from the sweep because this is the judgement that can lose keys,
/// and inside the wasm-only module it was reachable by no test at all: a
/// mutation that stopped counting undetermined delegates, and counted failed
/// re-imports as recoveries, passed fmt, clippy and the entire suite.
pub(crate) fn classify(
    reply: Result<ghostkey_common::GhostkeyResponse, crate::api::delegate::DelegateCallError>,
) -> ProbeVerdict {
    use crate::api::delegate::DelegateCallError;
    use ghostkey_common::GhostkeyResponse;

    match reply {
        Ok(GhostkeyResponse::ExportAllResult { keys }) => ProbeVerdict::Exported(keys),
        Err(DelegateCallError::NotRegistered) => ProbeVerdict::Skipped,
        Err(e) => ProbeVerdict::Undetermined(e.to_string()),
        // A definite refusal ("unsupported request variant", `PermissionDenied`)
        // is still undetermined for our purposes: it settles that we will get
        // nothing from this delegate, not that it is holding nothing.
        Ok(other) => ProbeVerdict::Undetermined(format!("unexpected reply: {other:?}")),
    }
}

/// Recover ghostkeys stored under earlier delegate versions.
///
/// `already_held` is the set of fingerprints the current delegate already has,
/// so a key present in both is neither re-imported nor reported as recovered
/// on every startup.
pub async fn try_migrate(already_held: Vec<String>) {
    #[cfg(all(
        target_family = "wasm",
        not(any(feature = "no-sync", feature = "example-data"))
    ))]
    real::run(already_held).await;

    #[cfg(not(all(
        target_family = "wasm",
        not(any(feature = "no-sync", feature = "example-data"))
    )))]
    let _ = already_held;
}

#[cfg(all(
    target_family = "wasm",
    not(any(feature = "no-sync", feature = "example-data"))
))]
mod real {
    use std::collections::BTreeSet;

    use dioxus::logger::tracing::{info, warn};
    use freenet_stdlib::prelude::{CodeHash, DelegateKey};
    use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};

    use super::{MigrationOutcome, ProbeVerdict};
    use crate::api;
    use crate::components::ghostkey_list;
    use crate::components::toast::{self, ToastKind};

    // Generated by build.rs from legacy_delegates.toml
    include!(concat!(env!("OUT_DIR"), "/legacy_delegates.rs"));

    /// Seconds to wait for a legacy delegate to answer.
    ///
    /// A delegate the node actually has is a local WASM call that answers in
    /// milliseconds, so this only ever bounds the wait for one the node does
    /// not have -- and those never answer, so the deadline is paid in full for
    /// each. At the previous 5s, ten entries meant ~50s of background probing
    /// on every vault open. Erring short is safe: a legacy delegate that does
    /// not answer in time is recorded as undetermined and the user is told,
    /// rather than being silently written off.
    const LEGACY_PROBE_TIMEOUT_SECS: u64 = 3;

    pub(super) async fn run(already_held: Vec<String>) {
        if LEGACY_DELEGATES.is_empty() {
            return;
        }

        info!(
            "Sweeping {} legacy delegate(s) for stored ghostkeys",
            LEGACY_DELEGATES.len()
        );

        let outcome = run_pass(already_held.into_iter().collect()).await;
        report(&outcome);
    }

    /// One sweep of the legacy delegate table.
    async fn run_pass(mut held: BTreeSet<String>) -> MigrationOutcome {
        let current_key = api::delegate::get_current_delegate_key();
        let mut outcome = MigrationOutcome::default();

        for (delegate_key_bytes, code_hash_bytes) in LEGACY_DELEGATES {
            let legacy_key = DelegateKey::new(*delegate_key_bytes, CodeHash::new(*code_hash_bytes));
            if legacy_key == current_key {
                continue;
            }

            let verdict = super::classify(
                api::delegate::send_to_delegate(
                    &legacy_key,
                    GhostkeyRequest::ExportAllGhostKeys,
                    LEGACY_PROBE_TIMEOUT_SECS,
                )
                .await,
            );
            outcome.record_probe(&verdict);

            let exported = match verdict {
                ProbeVerdict::Exported(keys) => keys,
                ProbeVerdict::Skipped => continue,
                ProbeVerdict::Undetermined(reason) => {
                    warn!(
                        "Legacy delegate {} undetermined: {reason}",
                        legacy_key.encode()
                    );
                    continue;
                }
            };

            for key in &exported {
                // Already in the current delegate: skip, so a predecessor that
                // keeps its copy forever does not re-import and re-announce
                // the same identities on every startup.
                if held.contains(&key.fingerprint) {
                    continue;
                }

                match api::delegate::send_request(GhostkeyRequest::ImportGhostKey {
                    certificate_pem: key.certificate_pem.clone(),
                    signing_key_pem: key.signing_key_pem.clone(),
                    master_verifying_key_pem: None,
                })
                .await
                {
                    Ok(GhostkeyResponse::ImportResult {
                        fingerprint,
                        notary_info,
                    }) => {
                        info!("Recovered ghostkey {fingerprint}");
                        held.insert(fingerprint.clone());
                        ghostkey_list::add_ghostkey(GhostKeyInfo {
                            fingerprint: fingerprint.clone(),
                            label: key.label.clone(),
                            notary_info,
                            verifying_key_bytes: None,
                        });
                        outcome.record_import(true);

                        if let Some(label) = &key.label {
                            let _ = api::delegate::send_request(GhostkeyRequest::SetLabel {
                                fingerprint,
                                label: label.clone(),
                            })
                            .await;
                        }
                    }
                    // The key is still only in the predecessor. Counting it as
                    // recovered would report a success that did not happen.
                    other => {
                        warn!("Could not re-import {}: {other:?}", key.fingerprint);
                        outcome.record_import(false);
                    }
                }
            }
        }

        outcome
    }

    fn report(outcome: &MigrationOutcome) {
        if outcome.recovered > 0 {
            toast::show(
                format!(
                    "Recovered {} ghostkey(s) from a previous vault version",
                    outcome.recovered
                ),
                ToastKind::Success,
            );
        }

        if outcome.needs_user_attention() {
            warn!(
                "Migration sweep incomplete: {} undetermined delegate(s), {} failed import(s)",
                outcome.undetermined, outcome.failed_imports
            );
            toast::show(
                "Could not check every previous vault version for stored ghostkeys. \
                 If an identity is missing, reopen the vault once your node is fully \
                 started, or re-import it from your backup.",
                ToastKind::Error,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(recovered: usize, undetermined: usize, failed_imports: usize) -> MigrationOutcome {
        MigrationOutcome {
            recovered,
            undetermined,
            failed_imports,
        }
    }

    #[test]
    fn a_pass_that_found_nothing_is_conclusive() {
        assert!(outcome(0, 0, 0).is_conclusive());
        assert!(!outcome(0, 0, 0).needs_user_attention());
    }

    #[test]
    fn a_pass_that_recovered_everything_is_conclusive() {
        assert!(outcome(3, 0, 0).is_conclusive());
        assert!(!outcome(3, 0, 0).needs_user_attention());
    }

    /// A legacy delegate we could not reach may still be holding keys, so the
    /// user has to be told rather than left with a silently partial sweep.
    #[test]
    fn an_undetermined_delegate_needs_user_attention() {
        let o = outcome(0, 1, 0);
        assert!(!o.is_conclusive());
        assert!(o.needs_user_attention());
    }

    /// A key pulled out of a predecessor but not re-imported is still only in
    /// the predecessor, even though the sweep otherwise completed.
    #[test]
    fn a_failed_import_needs_user_attention() {
        let o = outcome(1, 0, 1);
        assert!(!o.is_conclusive());
        assert!(o.needs_user_attention());
    }

    /// Recovering keys does not excuse an entry we could not check.
    #[test]
    fn recovery_does_not_mask_an_unchecked_delegate() {
        let o = outcome(5, 1, 0);
        assert!(o.needs_user_attention());
    }

    // --- Probe classification -------------------------------------------
    //
    // These exist because a review mutation proved the previous suite could
    // not see this code at all: dropping the undetermined count and counting
    // failed re-imports as recoveries passed fmt, clippy and every test, while
    // reproducing the stranded-keys symptom of #3.

    use crate::api::delegate::DelegateCallError;
    use ghostkey_common::GhostkeyResponse;

    #[test]
    fn an_export_reply_carries_its_keys_through() {
        let verdict = classify(Ok(GhostkeyResponse::ExportAllResult { keys: Vec::new() }));
        match verdict {
            ProbeVerdict::Exported(keys) => assert!(keys.is_empty()),
            other => panic!("expected Exported, got {other:?}"),
        }
    }

    /// The load-bearing distinction: "the node has no such delegate" and "the
    /// node did not answer" must NOT collapse into the same verdict. Treating
    /// a silence as a skip is how a delegate still holding keys gets passed
    /// over; treating a skip as undetermined warns every user forever.
    #[test]
    fn not_registered_and_no_answer_are_different_verdicts() {
        assert!(matches!(
            classify(Err(DelegateCallError::NotRegistered)),
            ProbeVerdict::Skipped
        ));
        assert!(matches!(
            classify(Err(DelegateCallError::TimedOut)),
            ProbeVerdict::Undetermined(_)
        ));
    }

    #[test]
    fn transport_and_delegate_failures_are_undetermined() {
        for err in [
            DelegateCallError::TimedOut,
            DelegateCallError::Failed("boom".into()),
            DelegateCallError::Transport("gone".into()),
        ] {
            match classify(Err(err.clone())) {
                // The reason is carried so the log names which delegate failed
                // and why; an empty one would make an inconclusive sweep
                // undiagnosable.
                ProbeVerdict::Undetermined(reason) => {
                    assert!(!reason.is_empty(), "{err:?} produced no reason")
                }
                other => panic!("{err:?} should be undetermined, got {other:?}"),
            }
        }
    }

    /// A definite refusal settles that we get nothing from this delegate, not
    /// that it holds nothing -- so it must not read as a clean skip.
    #[test]
    fn a_refusal_is_undetermined_not_skipped() {
        let verdict = classify(Ok(GhostkeyResponse::Error {
            message: "Unsupported request variant for this delegate version".into(),
        }));
        assert!(matches!(verdict, ProbeVerdict::Undetermined(_)));
    }

    // --- Outcome accumulation -------------------------------------------

    #[test]
    fn only_undetermined_probes_count_as_undetermined() {
        let mut o = MigrationOutcome::default();
        o.record_probe(&ProbeVerdict::Exported(Vec::new()));
        o.record_probe(&ProbeVerdict::Skipped);
        assert_eq!(o.undetermined, 0);

        o.record_probe(&ProbeVerdict::Undetermined("no answer".into()));
        assert_eq!(o.undetermined, 1);
        assert!(o.needs_user_attention());
    }

    /// A key that would not re-import is still only in the predecessor.
    /// Counting it as recovered reports a success that did not happen.
    #[test]
    fn a_failed_import_is_never_counted_as_recovered() {
        let mut o = MigrationOutcome::default();
        o.record_import(false);
        assert_eq!(o.recovered, 0);
        assert_eq!(o.failed_imports, 1);
        assert!(o.needs_user_attention());

        o.record_import(true);
        assert_eq!(o.recovered, 1);
        assert_eq!(o.failed_imports, 1);
    }
}
