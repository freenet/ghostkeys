//! Pins for the build-time legacy-delegate registry and the delegate-WASM
//! baseline.
//!
//! `ui/build.rs` turns `legacy_delegates.toml` into the `LEGACY_DELEGATES`
//! constant the recovery sweep probes. If that table ships stale, truncated,
//! or empty, the sweep asks the wrong delegates (or nobody) and users'
//! ghostkeys go quietly unreachable — the same failure class as
//! freenet/delta#52, from which this file's first two pins are ported.
//!
//! 1. [`the_baked_registry_matches_the_file_on_disk`] compares the constant
//!    Cargo baked in against the file read via `include_str!`. The
//!    `include_str!` copy is ALWAYS current (it lands in rustc's dep-info);
//!    the constant is only current if the build script re-ran. The asymmetry
//!    is the point: it goes red on a stale incremental build. Its parser is
//!    DELIBERATELY independent of `build.rs`'s (tolerant where build.rs is
//!    strict), so a formatting change build.rs mis-reads is caught rather
//!    than agreed with.
//! 2. [`every_file_the_build_script_reads_is_declared_to_cargo`] covers the
//!    cold-build case: a file the script reads but never declares via
//!    `rerun-if-changed` silently rots the generated table.
//! 3. [`registry_entries_are_internally_consistent`] re-checks
//!    `delegate_key == BLAKE3(code_hash)` independently of the build script's
//!    own assertion (and of `check-migration.sh`'s).
//! 4. [`delegate_wasm_is_byte_identical_to_the_recorded_baseline`] pins the
//!    delegate WASM bytes themselves.

use crate::migration_adapter::LEGACY_DELEGATES;

/// The registry file, read at compile time of the TEST binary.
const REGISTRY_TOML: &str = include_str!("../../legacy_delegates.toml");

/// The build script's own source, for the source pin below.
const BUILD_RS: &str = include_str!("../build.rs");

/// BLAKE3 of the delegate WASM that PR A (ghostkeys#33, stdlib 0.6→0.8)
/// produced, via the canonical path-remapped build. This PR — the
/// `freenet-migrate` adoption — is UI-side only and MUST NOT move the
/// delegate key: the stdlib bump and the crate adoption are designed to cross
/// exactly ONE re-key, together, at the next publish.
///
/// If you changed the delegate deliberately (source, a dependency the
/// delegate links, rust-toolchain), update this constant IN THE SAME PR and
/// say so in the PR body — the publish pipeline's `record-migration` covers
/// users either way, but an unnoticed re-key here means shipping TWO
/// migrations where one was planned.
const EXPECTED_DELEGATE_CODE_HASH: &str =
    "0d0e2043c5242953b6e8705179ca6847f1d83fce8e23a4ae314118d9b22ffd62";

/// Extract `(delegate_key, code_hash)` pairs by walking the file line by
/// line, tolerantly: any `key = "value"` spacing, comments skipped. Tolerance
/// is what makes this an independent oracle — `build.rs` REFUSES formats it
/// does not recognize, and this parser accepting them is how a
/// formatting-drift disagreement becomes visible as a red test rather than a
/// silently truncated table.
fn entries_in_registry_file() -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut current: Option<(Option<String>, Option<String>)> = None;

    let flush = |slot: &mut Option<(Option<String>, Option<String>)>,
                 out: &mut Vec<(String, String)>| {
        if let Some((Some(dk), Some(ch))) = slot.take() {
            out.push((dk, ch));
        }
    };

    for raw in REGISTRY_TOML.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if line == "[[entry]]" {
            flush(&mut current, &mut entries);
            current = Some((None, None));
            continue;
        }
        let Some(slot) = current.as_mut() else {
            continue;
        };
        if let Some(v) = quoted_value(line, "delegate_key") {
            slot.0 = Some(v);
        } else if let Some(v) = quoted_value(line, "code_hash") {
            slot.1 = Some(v);
        }
    }
    flush(&mut current, &mut entries);
    entries
}

/// Pull `value` out of a `key = "value"` line, if the line is that key.
fn quoted_value(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_baked_registry_matches_the_file_on_disk() {
    let from_file = entries_in_registry_file();

    // The parser is itself a thing that can silently break. If it stops
    // finding entries, every comparison below becomes vacuous, so assert it
    // found something before trusting it.
    assert!(
        from_file.len() >= 2,
        "parsed only {} entries out of legacy_delegates.toml — the test's own \
         parser has broken, so this pin is not checking anything. Fix the \
         parser before trusting a green run.",
        from_file.len()
    );

    let baked: Vec<(String, String)> = LEGACY_DELEGATES
        .iter()
        .map(|(dk, ch)| (hex(dk), hex(ch)))
        .collect();

    assert_eq!(
        baked,
        from_file,
        "The LEGACY_DELEGATES table compiled into this binary does not match \
         legacy_delegates.toml on disk ({} baked vs {} in the file).\n\n\
         Either ui/build.rs did not re-run after the file changed (check the \
         `cargo:rerun-if-changed=../legacy_delegates.toml` directive), or the file \
         has drifted into a format build.rs reads differently than this test does. \
         A bundle shipped in either state sweeps the wrong delegate table and \
         strands users' ghostkeys with no error anywhere.",
        baked.len(),
        from_file.len()
    );
}

#[test]
fn every_file_the_build_script_reads_is_declared_to_cargo() {
    // SOURCE PIN (scrapes ui/build.rs text, does not execute it).
    //
    // Cargo's rule: once a build script prints ANY `rerun-if-changed`, the
    // implicit "re-run when anything changes" fallback is switched off and
    // ONLY the declared paths are watched. So a file the script reads via
    // fs::read_to_string but never declares is invisible to Cargo — editing
    // it does not invalidate anything, and the generated table silently rots.
    let reads_registry = BUILD_RS.contains("legacy_delegates.toml");
    assert!(
        reads_registry,
        "build.rs no longer mentions legacy_delegates.toml; this pin needs updating \
         alongside whatever replaced it"
    );

    let needle = "cargo:rerun-if-changed=../legacy_delegates.toml";
    // Require the directive in an actual println!, anchored at the start of
    // the trimmed line, so a commented-out directive (which still contains
    // both `println!` and the needle) does not satisfy the pin — that exact
    // input defeated a `contains`-based version of this guard in Delta.
    let declared = BUILD_RS
        .lines()
        .any(|l| l.trim_start().starts_with("println!") && l.contains(needle));
    assert!(
        declared,
        "ui/build.rs reads legacy_delegates.toml but never prints `{needle}`. Cargo \
         will not re-run the build script when the registry changes, and the baked \
         sweep table ships stale — the freenet/delta#52 failure."
    );
}

#[test]
fn registry_entries_are_internally_consistent() {
    for (i, (dk, ch)) in LEGACY_DELEGATES.iter().enumerate() {
        let expected = blake3::hash(ch);
        assert_eq!(
            expected.as_bytes(),
            dk,
            "baked registry entry {} is inconsistent: delegate_key != BLAKE3(code_hash). \
             build.rs validates this at generation time, so this firing means the baked \
             table did not come from the current build.rs.",
            i + 1
        );
    }
}

/// The delegate WASM must be byte-identical to the PR-A baseline.
///
/// Reads the artifact the canonical build script produces. If it is missing,
/// this FAILS rather than skipping — a guard that silently skips is a guard
/// that cannot fail. CI builds the delegate (via `scripts/build-delegate.sh`)
/// before running tests; locally, `cargo make test` does the same.
///
/// If this fails with a DIFFERENT hash, first check HOW the artifact was
/// built: a bare `cargo build` skips the path remap and produces a
/// machine-specific hash that will never match (ghostkeys#34). Rebuild with
/// `cargo make build-delegate` before concluding the delegate changed.
#[test]
fn delegate_wasm_is_byte_identical_to_the_recorded_baseline() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read the delegate WASM at {}: {e}.\n\
             Build it first with `cargo make build-delegate` (NOT a bare cargo build — \
             see ghostkeys#34), then re-run the tests.",
            path.display()
        )
    });
    let hash = blake3::hash(&bytes);
    assert_eq!(
        hash.to_hex().to_string(),
        EXPECTED_DELEGATE_CODE_HASH,
        "the delegate WASM no longer matches the recorded baseline.\n\n\
         If you built it with a bare `cargo build`, rebuild with \
         `cargo make build-delegate` — the bare build skips the path remap and its \
         hash is machine-specific (ghostkeys#34).\n\n\
         If the canonical build really changed, something in this change re-keys the \
         delegate (source, Cargo.lock entries the delegate links, toolchain). Update \
         EXPECTED_DELEGATE_CODE_HASH only if that re-key is deliberate, and say so \
         in the PR body."
    );
}
