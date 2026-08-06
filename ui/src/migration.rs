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
    /// Legacy delegates that said they hold identities and then handed over
    /// nothing. Positive evidence of keys we cannot reach: reachable whenever
    /// the holder granted `Export` to somebody other than this vault, since
    /// importing needs no scope and grants the importer. Silence about this
    /// would be a clean-sweep report over keys that are gone for good.
    pub present_but_unexportable: usize,
    /// Legacy delegates that said they hold identities and then did not answer
    /// the export at all. NOT the ordinary silence of a delegate the node does
    /// not have -- this one already spoke -- so it is worth telling the user
    /// about, typically a dialog they missed.
    pub present_but_silent: usize,
    /// Legacy delegates the node reports it does not have. Ordinary and
    /// expected, but nothing ever re-registers legacy code, so if one of these
    /// does hold keys they are unreachable permanently.
    pub not_registered: usize,
    /// Delegates too old to answer `HasIdentity` that then exported nothing.
    ///
    /// Genuinely ambiguous: it means either "holds nothing" or "holds keys
    /// this vault cannot export", and the delegate is too old to tell us
    /// which. It is the OLDER half of the table, so the entries most likely to
    /// hold long-forgotten keys, which is why it is counted rather than
    /// dropped on the floor. It deliberately does NOT reach
    /// `needs_user_attention`: it would fire on essentially every node for
    /// every ancient entry, which is the crying-wolf failure this module's own
    /// comments warn about.
    pub unsettled_and_empty: usize,
}

impl MigrationOutcome {
    /// Whether every legacy delegate answered and every key it offered was
    /// re-imported. Purely a reporting distinction -- the sweep runs again on
    /// the next startup either way.
    pub(crate) fn is_conclusive(&self) -> bool {
        self.undetermined == 0
            && self.answered_with_error == 0
            && self.failed_imports == 0
            && self.present_but_unexportable == 0
            && self.present_but_silent == 0
            && self.not_registered == 0
            && self.unsettled_and_empty == 0
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
        self.failed_imports > 0
            || self.answered_with_error > 0
            // Both of these are a delegate that SAID it holds identities and
            // then did not hand them over. That is not the ordinary silence of
            // a delegate the node lacks, it is the shape of a user whose keys
            // did not come across, and it is the case a clean-looking sweep
            // would otherwise hide.
            || self.present_but_unexportable > 0
            || self.present_but_silent > 0
    }

    /// Record a probe verdict. `had_presence` says whether the delegate had
    /// already told us it holds identities, which is what separates "did not
    /// answer, like the ten others that are not installed" from "said it had
    /// keys and then went quiet".
    pub(crate) fn record_probe(&mut self, verdict: &ProbeVerdict, had_presence: bool) {
        match verdict {
            ProbeVerdict::Undetermined(_) if had_presence => self.present_but_silent += 1,
            ProbeVerdict::Undetermined(_) => self.undetermined += 1,
            ProbeVerdict::AnsweredWithError(_) => self.answered_with_error += 1,
            ProbeVerdict::Exported(keys) if keys.is_empty() => {
                if had_presence {
                    self.present_but_unexportable += 1
                } else {
                    self.unsettled_and_empty += 1
                }
            }
            ProbeVerdict::Exported(_) => {}
            ProbeVerdict::Skipped => self.not_registered += 1,
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

/// What the cheap, never-prompting presence question established.
///
/// Deliberately at module level rather than inside the wasm-only `mod real`.
/// The comment on `classify` above records that burying exactly this kind of
/// judgement in there once made a key-losing decision reachable by no test at
/// all; putting the next one back would repeat it.
/// No `Debug`/`PartialEq`: `NoAnswer` wraps a `ProbeVerdict`, which carries
/// `ExportedGhostKey` and therefore private signing keys. Tests compare
/// [`PresenceVerdict::kind`] instead, which is secret-free by construction.
pub(crate) enum PresenceVerdict {
    /// The delegate answered and holds nothing. Skip it without asking for
    /// keys, so no private-key dialog is raised for an empty predecessor.
    Empty,
    /// It answered and holds identities. Ask for the keys, and treat a later
    /// silence or empty answer as evidence rather than as routine absence.
    HoldsKeys,
    /// It answered in a way that does not settle the question -- an older
    /// delegate that does not know `HasIdentity` replies with an error, which
    /// is not "empty". Ask for the keys, but do not claim it had any.
    Unsettled,
    /// No answer, or a local failure. Carries the verdict to record.
    NoAnswer(ProbeVerdict),
}

/// The secret-free discriminant of a [`PresenceVerdict`], for assertions.
///
/// Test-only: the shipped code matches on `PresenceVerdict` itself. This
/// exists because that type cannot derive `PartialEq`/`Debug` without exposing
/// the private keys `ProbeVerdict` carries.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum PresenceKind {
    Empty,
    HoldsKeys,
    Unsettled,
    /// The node has no such delegate. Terminal: nothing re-registers legacy
    /// code, so keys under it stay unreachable.
    NotRegistered,
    /// Silence or a local failure.
    NoReply,
}

#[cfg(test)]
impl PresenceVerdict {
    pub(crate) fn kind(&self) -> PresenceKind {
        match self {
            PresenceVerdict::Empty => PresenceKind::Empty,
            PresenceVerdict::HoldsKeys => PresenceKind::HoldsKeys,
            PresenceVerdict::Unsettled => PresenceKind::Unsettled,
            PresenceVerdict::NoAnswer(ProbeVerdict::Skipped) => PresenceKind::NotRegistered,
            PresenceVerdict::NoAnswer(_) => PresenceKind::NoReply,
        }
    }
}

/// Decide what one presence reply means. Pure, so it is testable off wasm.
pub(crate) fn classify_presence(
    reply: Result<ghostkey_common::GhostkeyResponse, crate::api::delegate::DelegateCallError>,
) -> PresenceVerdict {
    use crate::api::delegate::DelegateCallError;
    use ghostkey_common::GhostkeyResponse;

    match reply {
        Ok(GhostkeyResponse::IdentityPresence { usable, unusable }) => {
            if usable == 0 && unusable == 0 {
                PresenceVerdict::Empty
            } else {
                PresenceVerdict::HoldsKeys
            }
        }
        // Same reading as `classify`: not registered is a fast skip, and it is
        // counted rather than ignored because nothing ever re-registers legacy
        // code, so keys under it are unreachable for good.
        Err(DelegateCallError::NotRegistered) => PresenceVerdict::NoAnswer(ProbeVerdict::Skipped),
        Err(DelegateCallError::TimedOut) => {
            PresenceVerdict::NoAnswer(ProbeVerdict::Undetermined("no reply".into()))
        }
        Err(DelegateCallError::Transport(reason)) => {
            PresenceVerdict::NoAnswer(ProbeVerdict::Undetermined(reason))
        }
        // A delegate-level failure, or any other reply, has not told us it is
        // empty. Ask for the keys.
        _ => PresenceVerdict::Unsettled,
    }
}

/// What the sweep should do with one legacy entry, given its presence reply.
///
/// Hoisted out of `run_pass` for the same reason `classify` and
/// `classify_presence` are: `run_pass` is wasm-only, so the DECISION -- as
/// opposed to the classification feeding it -- was reachable by no test at
/// all. Swapping two arms inside `run_pass` passed the whole suite.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SweepStep {
    /// Answered, holds nothing. Move on WITHOUT asking for keys, so no
    /// private-key dialog is raised for an empty predecessor.
    Skip,
    /// Did not answer. Record the verdict and move on.
    Record,
    /// Ask for the keys. `had_presence` is whether the delegate actually
    /// asserted it holds identities, which is what later separates "said it
    /// had keys and handed over none" from an ordinary empty predecessor.
    Export { had_presence: bool },
}

/// The decision itself. Pure, so the arms can be pinned.
pub(crate) fn sweep_step(verdict: &PresenceVerdict) -> SweepStep {
    match verdict {
        PresenceVerdict::Empty => SweepStep::Skip,
        PresenceVerdict::HoldsKeys => SweepStep::Export { had_presence: true },
        // Not "empty": a delegate too old to know the question has told us
        // nothing. Skipping it here would strand every key held by the oldest
        // entries in the table.
        PresenceVerdict::Unsettled => SweepStep::Export {
            had_presence: false,
        },
        PresenceVerdict::NoAnswer(_) => SweepStep::Record,
    }
}

use std::collections::BTreeSet;

/// Which default identity to adopt after a recovery pass.
///
/// `answers` is, per predecessor that supplied keys, the identity it treated
/// as its default and the set of fingerprints it actually handed over. The
/// first answer naming a key we now hold wins.
///
/// The containment check is the point: adopting a default that names a key
/// this vault does not hold would leave `SignWithDefault` resolving to nothing
/// or, worse, silently falling back to a different identity -- which is the
/// failure the carry-across exists to prevent, reintroduced from the other
/// side.
pub(crate) fn default_to_adopt(answers: &[(Option<String>, BTreeSet<String>)]) -> Option<String> {
    answers.iter().find_map(|(default, recovered)| {
        default
            .as_ref()
            .filter(|fp| recovered.contains(*fp))
            .cloned()
    })
}

/// Recover ghostkeys stored under earlier delegate versions.
///
/// `already_held` is the set of fingerprints the current delegate already has,
/// so a key present in both is neither re-imported nor reported as recovered
/// on every startup.
pub async fn try_migrate(already_held: Option<Vec<String>>) {
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

    /// Seconds to wait for the export itself, once a legacy delegate has shown
    /// it holds something.
    ///
    /// This one CAN involve a human. A delegate from this version onward
    /// requires a fresh user confirmation before it hands over private keys,
    /// so the reply arrives only after the user answers a dialog. Waiting less
    /// than the node's own dialog timeout would abandon the call while the
    /// dialog is still on screen, and the recovered keys would arrive with
    /// nobody waiting for them.
    ///
    /// One constant, shared with the current-delegate export path, so the two
    /// cannot drift.
    const LEGACY_EXPORT_TIMEOUT_SECS: u64 = api::delegate::USER_CONFIRMATION_TIMEOUT_SECS;

    pub(super) async fn run(already_held: Option<Vec<String>>) {
        if LEGACY_DELEGATES.is_empty() {
            // Not reachable in a normal build -- `build.rs` fails rather than
            // emit an empty table -- but if it ever were, silence would mean
            // migration had turned itself off with no signal anywhere.
            warn!("No legacy delegates compiled in; skipping the recovery sweep");
            return;
        }

        info!(
            "Sweeping {} legacy delegate(s) for stored ghostkeys",
            LEGACY_DELEGATES.len()
        );

        let known_held = already_held.is_some();
        let outcome = run_pass(
            already_held.unwrap_or_default().into_iter().collect(),
            known_held,
        )
        .await;
        report(&outcome);
    }

    /// One sweep of the legacy delegate table.
    /// `known_held` records whether `held` is trustworthy. When the current
    /// delegate could not be listed, every key looks new: the sweep would
    /// announce a recovery that did not happen and overwrite user-chosen
    /// labels with legacy ones.
    async fn run_pass(mut held: BTreeSet<String>, known_held: bool) -> MigrationOutcome {
        let current_key = api::delegate::get_current_delegate_key();
        let mut outcome = MigrationOutcome::default();
        // Which predecessor handed over which keys, so the default-identity
        // carry-over below only trusts a source that actually supplied the key
        // it names.
        let mut recovered_from: Vec<(DelegateKey, BTreeSet<String>)> = Vec::new();

        for (delegate_key_bytes, code_hash_bytes) in LEGACY_DELEGATES {
            let legacy_key = DelegateKey::new(*delegate_key_bytes, CodeHash::new(*code_hash_bytes));
            if legacy_key == current_key {
                continue;
            }

            // Ask a cheap question first, and only ask for the keys if the
            // answer says there are some.
            //
            // Asking for the keys outright used to be fine, because no
            // delegate ever prompted for them. From this version onward one
            // does, and an export probe against such a delegate would raise an
            // unexplained private-key dialog on every vault open -- including
            // for the eleven-or-so legacy entries that hold nothing -- and then
            // time out at 3s while the dialog was still up, stranding the keys
            // it was supposed to rescue and telling the user nothing.
            //
            // `HasIdentity` never prompts, by construction. A delegate too old
            // to know the request answers with an error rather than silence,
            // which is not "nothing to recover" -- so anything other than a
            // definite empty answer falls through to the export.
            let presence = presence_probe(&legacy_key).await;
            let had_presence = match super::sweep_step(&presence) {
                super::SweepStep::Skip => continue,
                super::SweepStep::Record => {
                    let super::PresenceVerdict::NoAnswer(verdict) = presence else {
                        unreachable!("only NoAnswer maps to Record")
                    };
                    outcome.record_probe(&verdict, false);
                    match &verdict {
                        ProbeVerdict::Undetermined(reason) => info!(
                            "Legacy delegate {} did not answer ({reason})",
                            legacy_key.encode()
                        ),
                        ProbeVerdict::Skipped => info!(
                            "Legacy delegate {} is not registered on this node",
                            legacy_key.encode()
                        ),
                        _ => {}
                    }
                    continue;
                }
                super::SweepStep::Export { had_presence } => had_presence,
            };

            let verdict = super::classify(
                api::delegate::send_to_delegate(
                    &legacy_key,
                    GhostkeyRequest::ExportAllGhostKeys,
                    LEGACY_EXPORT_TIMEOUT_SECS,
                )
                .await,
            );
            outcome.record_probe(&verdict, had_presence);

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

            let mut from_this_one: BTreeSet<String> = BTreeSet::new();
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
                let already_held = !known_held || held.contains(&key.fingerprint);

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
                        from_this_one.insert(fingerprint.clone());
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

            if !from_this_one.is_empty() {
                recovered_from.push((legacy_key.clone(), from_this_one));
            }
        }

        // The default-identity choice lives in the predecessor's secret
        // namespace, so a re-key loses it and `resolve_default` silently falls
        // back to the highest-tier key. `SignWithDefault` would then sign as a
        // DIFFERENT identity than before the update, with no prompt, for any
        // caller holding `Sign`. Carry it over.
        //
        // Only when this pass actually recovered something, which makes it a
        // once-per-migration event rather than something that fights a choice
        // the user makes later.
        if outcome.recovered > 0 {
            carry_default_identity(&recovered_from).await;
        }

        outcome
    }

    /// Ask each predecessor that supplied keys which identity it treated as
    /// the default, and adopt the first answer naming a key we now hold.
    async fn carry_default_identity(sources: &[(DelegateKey, BTreeSet<String>)]) {
        let Some(fp) = default_key_from(sources).await else {
            return;
        };
        match api::delegate::send_request(GhostkeyRequest::SetDefaultKey {
            fingerprint: fp.clone(),
        })
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

    async fn default_key_from(sources: &[(DelegateKey, BTreeSet<String>)]) -> Option<String> {
        let mut answers: Vec<(Option<String>, BTreeSet<String>)> = Vec::new();
        for (legacy_key, recovered) in sources {
            let answer = match api::delegate::send_to_delegate(
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
        super::default_to_adopt(&answers)
    }

    async fn presence_probe(legacy_key: &DelegateKey) -> super::PresenceVerdict {
        super::classify_presence(
            api::delegate::send_to_delegate(
                legacy_key,
                GhostkeyRequest::HasIdentity,
                LEGACY_PROBE_TIMEOUT_SECS,
            )
            .await,
        )
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
            // Every counter, or the line contradicts itself: it used to
            // enumerate three while `is_conclusive` was broken by six, so it
            // could print "0 silent, 0 answered with an error, 0 failed
            // imports" directly beneath the claim that the sweep was
            // incomplete. A debugging aid that reports all zeros for a failure
            // is worse than none.
            warn!(
                "Migration sweep incomplete: {} silent, {} not registered, {} answered with an error, \
                 {} failed import(s), {} held keys we could not export, {} held keys then went silent, \
                 {} too old to ask and exported nothing",
                outcome.undetermined,
                outcome.not_registered,
                outcome.answered_with_error,
                outcome.failed_imports,
                outcome.present_but_unexportable,
                outcome.present_but_silent,
                outcome.unsettled_and_empty
            );
        }

        if !outcome.needs_user_attention() {
            return;
        }

        // Every condition `needs_user_attention` is true for needs a branch
        // here. Without one, the gate passes and the user is shown nothing --
        // which is exactly the silent-clean-sweep failure the counters were
        // added to end.
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
        } else if outcome.present_but_silent > 0 {
            toast::show(
                "A previous vault version has identities stored but did not hand \
                 them over. If it asked you to confirm and the prompt was missed, \
                 reload the vault and allow it. Otherwise re-import from your backup.",
                ToastKind::Error,
            );
        } else if outcome.present_but_unexportable > 0 {
            toast::show(
                "A previous vault version holds identities this vault could not \
                 read. If one is missing here, re-import it from your backup.",
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
            failed_imports,
            ..MigrationOutcome::default()
        }
    }

    /// An empty predecessor is skipped without asking for keys. This is what
    /// keeps the private-key dialog from firing on every vault open for the
    /// legacy entries that hold nothing.
    #[test]
    fn an_empty_predecessor_is_skipped() {
        assert_eq!(
            classify_presence(Ok(GhostkeyResponse::IdentityPresence {
                usable: 0,
                unusable: 0
            }))
            .kind(),
            PresenceKind::Empty
        );
    }

    #[test]
    fn a_predecessor_holding_keys_is_asked_for_them() {
        for (usable, unusable) in [(1, 0), (0, 1), (3, 2)] {
            assert_eq!(
                classify_presence(Ok(GhostkeyResponse::IdentityPresence { usable, unusable }))
                    .kind(),
                PresenceKind::HoldsKeys,
                "({usable}, {unusable}) must be treated as holding keys"
            );
        }
    }

    /// A delegate too old to know `HasIdentity` answers with an error. That is
    /// NOT "empty" -- treating it as empty would skip a predecessor that holds
    /// every key the user has, which is the whole population being migrated
    /// from today.
    #[test]
    fn a_delegate_that_does_not_know_the_question_is_still_asked_for_keys() {
        assert_eq!(
            classify_presence(Ok(GhostkeyResponse::Error {
                message: "Unsupported request variant for this delegate version".into()
            }))
            .kind(),
            PresenceKind::Unsettled
        );
        assert_eq!(
            classify_presence(Ok(GhostkeyResponse::NoIdentityAvailable)).kind(),
            PresenceKind::Unsettled
        );
    }

    /// Silence must not raise a dialog, and must not be mistaken for empty.
    #[test]
    fn silence_does_not_lead_to_an_export_attempt() {
        assert_eq!(
            classify_presence(Err(DelegateCallError::TimedOut)).kind(),
            PresenceKind::NoReply
        );
        assert_eq!(
            classify_presence(Err(DelegateCallError::Transport("socket".into()))).kind(),
            PresenceKind::NoReply
        );
    }

    /// A delegate the node does not have is terminal, not transient: nothing
    /// re-registers legacy code. It is counted so a sweep that passed over one
    /// cannot call itself conclusive.
    #[test]
    fn an_unregistered_predecessor_is_counted_not_ignored() {
        assert_eq!(
            classify_presence(Err(DelegateCallError::NotRegistered)).kind(),
            PresenceKind::NotRegistered
        );

        let mut o = MigrationOutcome::default();
        o.record_probe(&ProbeVerdict::Skipped, false);
        assert_eq!(o.not_registered, 1);
        assert!(
            !o.is_conclusive(),
            "a skipped predecessor is not a clean sweep"
        );
    }

    /// A predecessor that SAID it holds identities and then handed over
    /// nothing is positive evidence of keys we cannot reach. Reachable
    /// whenever some other app imported the key, since importing needs no
    /// scope and grants the importer.
    #[test]
    fn present_but_unexportable_is_surfaced() {
        let mut o = MigrationOutcome::default();
        o.record_probe(&ProbeVerdict::Exported(Vec::new()), true);
        assert_eq!(o.present_but_unexportable, 1);
        assert!(!o.is_conclusive());
        assert!(
            o.needs_user_attention(),
            "keys that exist and cannot be recovered must not be reported as a clean sweep"
        );
    }

    /// Presence positive followed by silence is not the ordinary absence case
    /// -- this delegate already spoke -- so it must not be bucketed with it.
    #[test]
    fn present_then_silent_is_not_ordinary_absence() {
        let mut o = MigrationOutcome::default();
        o.record_probe(&ProbeVerdict::Undetermined("no reply".into()), true);
        assert_eq!(o.present_but_silent, 1);
        assert_eq!(o.undetermined, 0, "must not be filed as routine silence");
        assert!(o.needs_user_attention());

        let mut ordinary = MigrationOutcome::default();
        ordinary.record_probe(&ProbeVerdict::Undetermined("no reply".into()), false);
        assert_eq!(ordinary.undetermined, 1);
        assert!(
            !ordinary.needs_user_attention(),
            "a delegate the node lacks is the normal case and must stay quiet"
        );
    }

    /// An export that produced keys is unremarkable whether or not presence
    /// was reported.
    #[test]
    fn a_successful_export_is_not_flagged() {
        let mut o = MigrationOutcome::default();
        o.record_probe(
            &ProbeVerdict::Exported(vec![ghostkey_common::ExportedGhostKey {
                fingerprint: "fp".into(),
                certificate_pem: String::new(),
                signing_key_pem: String::new(),
                label: None,
                notary_info: String::new(),
            }]),
            true,
        );
        assert!(o.is_conclusive());
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// The sweep's per-entry decision, not just the classification feeding it.
    /// Swapping two of these arms used to pass the entire suite.
    #[test]
    fn an_empty_predecessor_is_skipped_and_an_unsettled_one_is_not() {
        assert_eq!(sweep_step(&PresenceVerdict::Empty), SweepStep::Skip);
        assert_eq!(
            sweep_step(&PresenceVerdict::Unsettled),
            SweepStep::Export {
                had_presence: false
            },
            "a delegate too old to know the question has NOT said it is empty"
        );
        assert_eq!(
            sweep_step(&PresenceVerdict::HoldsKeys),
            SweepStep::Export { had_presence: true }
        );
        assert_eq!(
            sweep_step(&PresenceVerdict::NoAnswer(ProbeVerdict::Skipped)),
            SweepStep::Record
        );
    }

    /// An old predecessor that exports nothing is ambiguous, so it is counted
    /// rather than dropped -- but it must not put a warning in front of every
    /// user on every open.
    #[test]
    fn an_old_predecessor_exporting_nothing_is_counted_but_not_alarming() {
        let mut o = MigrationOutcome::default();
        o.record_probe(&ProbeVerdict::Exported(Vec::new()), false);
        assert_eq!(o.unsettled_and_empty, 1);
        assert_eq!(o.present_but_unexportable, 0);
        assert!(!o.is_conclusive(), "it is logged");
        assert!(!o.needs_user_attention(), "but it is not news");
    }

    #[test]
    fn the_default_identity_comes_from_a_predecessor_that_supplied_it() {
        assert_eq!(
            default_to_adopt(&[(Some("fpA".into()), set(&["fpA", "fpB"]))]),
            Some("fpA".to_string())
        );
    }

    /// A default naming a key we did not recover must be ignored, or
    /// `SignWithDefault` resolves to nothing or to some other identity.
    #[test]
    fn a_default_naming_a_key_we_do_not_hold_is_ignored() {
        assert_eq!(
            default_to_adopt(&[(Some("fpZ".into()), set(&["fpA"]))]),
            None
        );
        assert_eq!(default_to_adopt(&[(None, set(&["fpA"]))]), None);
        assert_eq!(default_to_adopt(&[]), None);
    }

    #[test]
    fn the_first_usable_answer_wins() {
        assert_eq!(
            default_to_adopt(&[
                (Some("fpZ".into()), set(&["fpA"])),
                (Some("fpB".into()), set(&["fpB"])),
            ]),
            Some("fpB".to_string())
        );
    }

    /// The sweep code is wasm-only, so nothing else here can observe that the
    /// carry-across is actually WIRED IN. It was written once, lost to a
    /// stray checkout, and compiled warning-free afterwards because the
    /// leftover scaffolding still counted as a use. This pins the wiring.
    #[test]
    fn the_sweep_carries_the_default_identity_across() {
        // Only the code above the test module, so the needles below cannot
        // match themselves through `include_str!`.
        let src = include_str!("migration.rs");
        let code = src
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .expect("test module marker");

        for needle in [
            "SetDefaultKey",
            "default_to_adopt",
            "carry_default_identity",
        ] {
            assert!(
                code.contains(needle),
                "the default-identity carry-across is not wired in: `{needle}` is missing"
            );
        }
        assert!(
            code.contains("if outcome.recovered > 0 {"),
            "the carry-across must be gated on a pass that actually recovered something, \
             or it fights a choice the user makes later"
        );
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
        o.record_probe(&verdict, false);
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
        o.record_probe(&verdict, false);
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
        o.record_probe(&ProbeVerdict::Exported(Vec::new()), false);
        o.record_probe(&ProbeVerdict::Skipped, false);
        assert_eq!(o.undetermined, 0);

        o.record_probe(&ProbeVerdict::Undetermined("no answer".into()), false);
        assert_eq!(o.undetermined, 1);
        assert_eq!(o.answered_with_error, 0);
        assert!(!o.needs_user_attention(), "counted, but not user-facing");

        o.record_probe(&ProbeVerdict::AnsweredWithError("refused".into()), false);
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
