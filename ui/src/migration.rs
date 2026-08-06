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
    /// Legacy delegates that never answered at all. Silence is the ordinary
    /// case for a delegate the node does not have, so this is counted for the
    /// log and deliberately not shown to the user.
    pub undetermined: usize,
    /// Legacy delegates that DID answer, with a failure. Unlike silence this
    /// is positive evidence: something is there and we could not read it --
    /// a missing secret, or a refusal. Kept separate precisely so the
    /// crying-wolf fix for silence does not also mute this.
    pub answered_with_error: usize,
    /// Keys a legacy delegate handed over that would not re-import.
    pub failed_imports: usize,
}

impl MigrationOutcome {
    /// Whether every legacy delegate answered and every key it offered was
    /// re-imported. Purely a reporting distinction -- the sweep runs again on
    /// the next startup either way.
    pub(crate) fn is_conclusive(&self) -> bool {
        self.undetermined == 0 && self.answered_with_error == 0 && self.failed_imports == 0
    }

    /// Whether the user needs telling.
    ///
    /// Deliberately NOT "the sweep was inconclusive". A node does not answer a
    /// probe for a delegate it does not have -- measured rather than assumed:
    /// nine legacy entries produced nine timeouts and no error response for
    /// any of them. So an undetermined probe is the NORMAL case on any node
    /// that has not run every previous vault version, which is essentially
    /// every node. Warning on it would put a red error in front of every user
    /// on every open, forever, and train them to dismiss the one warning that
    /// would matter. It stays counted and logged, but it is not news.
    ///
    /// A failed import is different: a legacy delegate handed us a key and we
    /// could not bring it over. That is positive evidence of something
    /// recoverable that was not recovered, it is rare, and the user can act on
    /// it by re-importing from their backup.
    pub(crate) fn needs_user_attention(&self) -> bool {
        self.failed_imports > 0 || self.answered_with_error > 0
    }

    pub(crate) fn record_probe(&mut self, verdict: &ProbeVerdict) {
        match verdict {
            ProbeVerdict::Undetermined(_) => self.undetermined += 1,
            ProbeVerdict::AnsweredWithError(_) => self.answered_with_error += 1,
            ProbeVerdict::Exported(_) | ProbeVerdict::Skipped => {}
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
/// Neither `PartialEq` nor a derived `Debug`: `ExportedGhostKey` carries the
/// private signing key, so a derive would print it into the browser console
/// the first time anyone formatted a verdict, and an `==` would invite
/// comparing secrets by value.
#[derive(Clone)]
pub(crate) enum ProbeVerdict {
    /// The delegate answered with the keys it holds, possibly none.
    Exported(Vec<ghostkey_common::ExportedGhostKey>),
    /// Nothing actionable, and nothing to worry about right now. Notably NOT
    /// a claim that the delegate holds nothing -- see
    /// `DelegateCallError::NotRegistered`. Since the sweep seals nothing, a
    /// wrong read here costs one pass, not permanence.
    Skipped,
    /// No answer at all. The delegate may be holding keys we could not see,
    /// but silence is also exactly what a delegate the node does not have
    /// looks like, so this alone is not news.
    Undetermined(String),
    /// The delegate answered, with a failure. Something is there and we could
    /// not read it, which IS worth telling the user about.
    AnsweredWithError(String),
}

impl std::fmt::Debug for ProbeVerdict {
    /// Hand-written so the key count is visible and the key material is not.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exported(keys) => write!(f, "Exported({} key(s))", keys.len()),
            Self::Skipped => write!(f, "Skipped"),
            Self::Undetermined(reason) => write!(f, "Undetermined({reason})"),
            Self::AnsweredWithError(reason) => write!(f, "AnsweredWithError({reason})"),
        }
    }
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
        // Neither of these is an answer. `TimedOut` is silence, and
        // `Transport` is produced entirely locally -- a serialize failure, a
        // dead socket -- meaning we never got to ask. Counting it as an
        // answered failure would put the red toast in front of a user whose
        // websocket dropped mid-sweep, on a node that may hold no legacy
        // delegates at all, while the connection banner already says so.
        Err(DelegateCallError::TimedOut) => ProbeVerdict::Undetermined("no reply".into()),
        Err(DelegateCallError::Transport(reason)) => ProbeVerdict::Undetermined(reason),
        // A delegate-level failure DID come back from somewhere.
        Err(e) => ProbeVerdict::AnsweredWithError(e.to_string()),
        // A refusal ("unsupported request variant", `PermissionDenied`) is
        // also an answer: it settles that we get nothing from this delegate,
        // not that it holds nothing.
        //
        // Only the variant NAME goes in the reason. `GhostkeyResponse` derives
        // Debug and its export variants carry `signing_key_pem`, so formatting
        // the payload here would put private keys in the browser console.
        Ok(other) => ProbeVerdict::AnsweredWithError(format!(
            "unexpected reply: {}",
            crate::api::delegate::response_kind(&other)
        )),
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
                    info!(
                        "Legacy delegate {} did not answer ({reason})",
                        legacy_key.encode()
                    );
                    continue;
                }
                ProbeVerdict::AnsweredWithError(reason) => {
                    warn!(
                        "Legacy delegate {} answered with an error: {reason}",
                        legacy_key.encode()
                    );
                    continue;
                }
            };

            for key in &exported {
                // Import even a fingerprint the current delegate already
                // lists. `ListGhostKeys` reports a key whenever its
                // CERTIFICATE loads and never checks the signing key, while a
                // legacy delegate only ever offers a complete pair -- so a key
                // whose cert survived but whose signing key did not looks
                // present, cannot sign, and skipping it would strand it in
                // that state forever. Re-importing overwrites both halves and
                // heals it; `handle_import` is idempotent and dedupes.
                //
                // What must NOT repeat is the announcing: counting it as a
                // recovery, or restoring the legacy label over a name the user
                // has since chosen.
                let already_held = held.contains(&key.fingerprint);

                match api::delegate::send_request(GhostkeyRequest::ImportGhostKey {
                    certificate_pem: key.certificate_pem.clone(),
                    signing_key_pem: key.signing_key_pem.clone(),
                })
                .await
                {
                    Ok(GhostkeyResponse::ImportResult {
                        fingerprint,
                        notary_info,
                    }) => {
                        held.insert(fingerprint.clone());
                        ghostkey_list::add_ghostkey(GhostKeyInfo {
                            fingerprint: fingerprint.clone(),
                            label: key.label.clone(),
                            notary_info,
                            verifying_key_bytes: None,
                            // The backup marker lives in the delegate's own
                            // secret namespace, which a re-key moves, so a
                            // recovered key always starts un-marked. That
                            // over-warns rather than under-warns, which is the
                            // direction to err in when the cost is the key.
                            backed_up: false,
                        });

                        if already_held {
                            // Refreshed an identity we already had; nothing to
                            // announce and no label to restore.
                            continue;
                        }

                        info!("Recovered ghostkey {fingerprint}");
                        outcome.record_import(true);

                        if let Some(label) = &key.label {
                            // Only label the key we actually asked to import.
                            // This fingerprint is echoed by the delegate, and a
                            // mis-delivered reply (see `claim_waiter`) would
                            // otherwise write THIS key's label onto ANOTHER
                            // key. That is a durable write, and the one case
                            // that does NOT self-correct: the next startup sees
                            // that key as already held and skips this path, so
                            // a silently renamed identity stays renamed.
                            //
                            // Comparing rather than substituting, because a
                            // legacy delegate is not guaranteed to compute
                            // fingerprints the way the current one does; on a
                            // mismatch the safe action is to skip a cosmetic
                            // write, not to guess a target for it.
                            if fingerprint == key.fingerprint {
                                let _ = api::delegate::send_request(GhostkeyRequest::SetLabel {
                                    fingerprint,
                                    label: label.clone(),
                                })
                                .await;
                            } else {
                                warn!(
                                    "Not labelling {}: delegate echoed a different fingerprint ({fingerprint})",
                                    key.fingerprint
                                );
                            }
                        }
                    }
                    // The key is still only in the predecessor. Counting it as
                    // recovered would report a success that did not happen.
                    Ok(other) => {
                        warn!(
                            "Could not re-import {}: {}",
                            key.fingerprint,
                            crate::api::delegate::response_kind(&other)
                        );
                        // Only a failure to bring over a key we do NOT already
                        // have is worth reporting; a failed refresh of one we
                        // already hold leaves the user no worse off.
                        if !already_held {
                            outcome.record_import(false);
                        }
                    }
                    Err(e) => {
                        warn!("Could not re-import {}: {e}", key.fingerprint);
                        if !already_held {
                            outcome.record_import(false);
                        }
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

        if !outcome.is_conclusive() {
            // Logged, not shown. On a healthy node most legacy entries simply
            // do not answer, so this is the ordinary case rather than a fault.
            warn!(
                "Migration sweep incomplete: {} silent delegate(s), {} answered with an error, {} failed import(s)",
                outcome.undetermined, outcome.answered_with_error, outcome.failed_imports
            );
        }

        if !outcome.needs_user_attention() {
            return;
        }

        if outcome.failed_imports > 0 {
            toast::show(
                format!(
                    "Found {} ghostkey(s) in a previous vault version but could not \
                     import them. Re-import from your backup, or reopen the vault \
                     once your node is fully started.",
                    outcome.failed_imports
                ),
                ToastKind::Error,
            );
        } else if outcome.answered_with_error > 0 {
            toast::show(
                "A previous vault version reported a problem reading one of its \
                 stored identities. If one is missing here, re-import it from \
                 your backup.",
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
            answered_with_error: 0,
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

    /// A delegate that did not answer is recorded, but must NOT reach the
    /// user. A node does not answer a probe for a delegate it does not have,
    /// so on any node that has not run every previous vault version -- which
    /// is essentially every node -- this is the ordinary case. Warning on it
    /// puts a red error in front of everyone on every open, forever.
    #[test]
    fn an_undetermined_delegate_is_recorded_but_not_reported() {
        let o = outcome(0, 9, 0);
        assert!(!o.is_conclusive(), "still counted for the log");
        assert!(!o.needs_user_attention(), "must not warn the user");
    }

    /// A key pulled out of a predecessor but not re-imported is still only in
    /// the predecessor. That is positive evidence of something recoverable
    /// that was not recovered, and the user can act on it.
    #[test]
    fn a_failed_import_is_reported() {
        let o = outcome(1, 0, 1);
        assert!(!o.is_conclusive());
        assert!(o.needs_user_attention());
    }

    /// Recovering keys does not excuse one we could not bring over.
    #[test]
    fn recovery_does_not_mask_a_failed_import() {
        assert!(outcome(5, 0, 1).needs_user_attention());
    }

    /// The two signals are independent: silence never promotes itself into a
    /// warning by piling up.
    #[test]
    fn undetermined_probes_never_add_up_to_a_warning() {
        assert!(!outcome(0, 100, 0).needs_user_attention());
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

    /// Silence and a failure that came back FROM somewhere are different
    /// things: silence is the ordinary case for a delegate the node lacks,
    /// while an answered failure means something is there we could not read.
    /// Collapsing them either warns everybody forever or warns nobody.
    #[test]
    fn silence_and_an_answered_failure_are_different_verdicts() {
        assert!(matches!(
            classify(Err(DelegateCallError::TimedOut)),
            ProbeVerdict::Undetermined(_)
        ));

        // A local transport failure means we never got to ask, so it belongs
        // with silence rather than with answers.
        assert!(matches!(
            classify(Err(DelegateCallError::Transport("socket closed".into()))),
            ProbeVerdict::Undetermined(_)
        ));

        for err in [DelegateCallError::Failed("missing secret gk:sk:abc".into())] {
            match classify(Err(err.clone())) {
                ProbeVerdict::AnsweredWithError(reason) => {
                    assert!(!reason.is_empty(), "{err:?} produced no reason")
                }
                other => panic!("{err:?} should be an answered failure, got {other:?}"),
            }
        }
    }

    /// A refusal settles that we get nothing from this delegate, not that it
    /// holds nothing -- so it must not read as a clean skip, and the user
    /// should hear about it.
    #[test]
    fn a_refusal_is_an_answered_failure_not_a_skip() {
        let verdict = classify(Ok(GhostkeyResponse::Error {
            message: "Unsupported request variant for this delegate version".into(),
        }));
        assert!(matches!(verdict, ProbeVerdict::AnsweredWithError(_)));

        let mut o = MigrationOutcome::default();
        o.record_probe(&verdict);
        assert!(
            o.needs_user_attention(),
            "an answered failure is reportable"
        );
    }

    /// A legacy delegate holding a key whose signing key is gone answers
    /// `MissingSecret`. That user has an unrecoverable identity and must be
    /// told -- it is exactly the evidence the silence rule must not mute.
    #[test]
    fn a_missing_secret_reaches_the_user() {
        let verdict = classify(Err(DelegateCallError::Failed("missing secret".into())));
        let mut o = MigrationOutcome::default();
        o.record_probe(&verdict);
        assert!(o.needs_user_attention());
    }

    /// Diagnostics on this path must never format a response payload:
    /// `GhostkeyResponse` derives Debug and its export variants carry the
    /// private signing key, so one `{response:?}` would print it to the
    /// browser console.
    #[test]
    fn a_reply_is_named_never_dumped() {
        const SECRET: &str = "-----BEGIN ED25519_SIGNING_KEY_V1-----SUPERSECRET";
        let reply = GhostkeyResponse::ExportResult {
            fingerprint: "abc".into(),
            certificate_pem: "cert".into(),
            signing_key_pem: SECRET.into(),
            label: None,
        };
        assert_eq!(crate::api::delegate::response_kind(&reply), "ExportResult");

        let verdict = classify(Ok(reply));
        let rendered = format!("{verdict:?}");
        assert!(
            !rendered.contains("SUPERSECRET"),
            "verdict leaked key material: {rendered}"
        );
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
        assert_eq!(o.answered_with_error, 0);
        assert!(!o.needs_user_attention(), "counted, but not user-facing");

        o.record_probe(&ProbeVerdict::AnsweredWithError("refused".into()));
        assert_eq!(o.undetermined, 1, "silence and failures stay separate");
        assert_eq!(o.answered_with_error, 1);
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
