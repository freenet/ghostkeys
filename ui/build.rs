use std::fs;
use std::process::Command;

fn main() {
    // Cargo watches ONLY the paths named here once any `rerun-if-changed` is
    // emitted. The script previously named just `build.rs` and the legacy
    // table, so editing UI source did not re-run it and BUILD_TIMESTAMP_ISO /
    // GIT_COMMIT kept whatever values they had the last time it happened to
    // run. The vault then footered a stale "Built:" line -- the single thing
    // someone checks to confirm a deploy landed. It read four hours old
    // immediately after the 2026-08-03 publish of freshly built code, and
    // very nearly passed for a failed deploy.
    //
    // Naming `src` (cargo walks directories recursively) covers the UI's own
    // code; the other two live outside the package and so must be named
    // individually.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../legacy_delegates.toml");
    // Embedded by `api::delegate` via include_bytes!, so a delegate-only
    // change ships in this bundle and must refresh the stamp too.
    println!(
        "cargo:rerun-if-changed=../target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"
    );

    // Build timestamp
    let now = chrono::Utc::now();
    let build_timestamp_iso = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    println!("cargo:rustc-env=BUILD_TIMESTAMP_ISO={build_timestamp_iso}");

    // Git commit
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_COMMIT={git_hash}");

    // Generate LEGACY_DELEGATES const from legacy_delegates.toml
    generate_legacy_delegates();
}

fn generate_legacy_delegates() {
    let toml_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../legacy_delegates.toml");
    let content = match fs::read_to_string(toml_path) {
        Ok(c) => c,
        // Fail the build rather than emit an empty table. An empty table
        // silently disables migration: the sweep finds no entries, returns
        // immediately, and every user's ghostkeys stay stranded under the
        // previous delegate with nothing logged anywhere. A missing or
        // unreadable table is a broken checkout, not a valid "no predecessors"
        // state -- that state is an EMPTY file, which parses fine below.
        Err(e) => panic!("cannot read {toml_path}: {e}. Migration would be silently disabled."),
    };

    let mut entries: Vec<(String, String)> = Vec::new();

    // Line scanner for [[entry]] blocks. Deliberately NOT the `toml` crate:
    // record-migration.sh and check-migration.sh read this file with greps of
    // the same shape, so the one format everything agrees on is the literal
    // one those scripts append. What was WRONG with the previous version of
    // this scanner was not its strictness but its silence: a line the scanner
    // did not recognize was simply dropped, so a reformatted-but-valid TOML
    // (extra spaces, single quotes) compiled to an EMPTY or truncated table
    // with no error anywhere -- the exact stale-table failure that stranded
    // Delta's users. Every cross-check below turns that silence into a build
    // failure.
    let mut current_delegate_key: Option<String> = None;
    let mut current_code_hash: Option<String> = None;
    let mut declared_entries = 0usize;

    fn flush(entries: &mut Vec<(String, String)>, dk: Option<String>, ch: Option<String>) {
        match (dk, ch) {
            (Some(dk), Some(ch)) => entries.push((dk, ch)),
            (None, None) => {} // the prologue before the first [[entry]]
            (dk, ch) => panic!(
                "legacy_delegates.toml has a half-parsed entry \
                 (delegate_key: {}, code_hash: {}). Either the file is corrupt or this \
                 scanner no longer recognizes its format. Refusing to bake a table that \
                 would silently drop an entry -- every dropped entry orphans the users \
                 running that delegate.",
                dk.is_some(),
                ch.is_some()
            ),
        }
    }

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[entry]]" {
            declared_entries += 1;
            flush(
                &mut entries,
                current_delegate_key.take(),
                current_code_hash.take(),
            );
        } else if let Some(val) = quoted_value(line, "delegate_key") {
            current_delegate_key = Some(val);
        } else if let Some(val) = quoted_value(line, "code_hash") {
            current_code_hash = Some(val);
        } else {
            // An unrecognized non-comment line is the reformatted-TOML case:
            // valid TOML this scanner cannot read compiles to a table missing
            // whatever that line carried. Fail instead.
            panic!(
                "legacy_delegates.toml contains a line this scanner does not recognize: \
                 `{line}`. The generated sweep table would silently omit it. Restore the \
                 canonical `key = \"hex\"` formatting (record-migration.sh appends it) or \
                 teach build.rs AND the check/record scripts the new format together."
            );
        }
    }
    flush(&mut entries, current_delegate_key, current_code_hash);

    // Every [[entry]] header must have produced exactly one table row.
    assert_eq!(
        entries.len(),
        declared_entries,
        "legacy_delegates.toml declares {declared_entries} [[entry]] block(s) but only \
         {} parsed. A dropped entry orphans every user running that delegate.",
        entries.len()
    );

    // Each entry must be internally consistent: the delegate key is BLAKE3
    // over the raw bytes of the code hash (parameters are empty). A mistyped
    // or hand-edited entry points the sweep at a delegate that never existed,
    // so it probes, times out, and reports nothing wrong -- a silent hole in
    // exactly the table that exists to prevent silent holes. Same rule as
    // scripts/check-migration.sh, enforced here so a bundle can never ship an
    // entry the publish gate would refuse.
    for (i, (dk, ch)) in entries.iter().enumerate() {
        let ch_bytes = hex32(ch, i, "code_hash");
        let dk_bytes = hex32(dk, i, "delegate_key");
        let expected = blake3::hash(&ch_bytes);
        assert_eq!(
            expected.as_bytes(),
            &dk_bytes,
            "legacy_delegates.toml entry {} is inconsistent: delegate_key must be BLAKE3 \
             over the raw bytes of code_hash (expected {}, recorded {dk}). Do not \
             hand-edit the file -- use `cargo make add-migration`.",
            i + 1,
            expected.to_hex()
        );
    }

    // Generate Rust code
    let mut code = String::from("pub const LEGACY_DELEGATES: &[([u8; 32], [u8; 32])] = &[\n");
    for (dk, ch) in &entries {
        let dk_bytes = hex_to_byte_array(dk);
        let ch_bytes = hex_to_byte_array(ch);
        code.push_str(&format!("    ({dk_bytes}, {ch_bytes}),\n"));
    }
    code.push_str("];\n");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    fs::write(format!("{out_dir}/legacy_delegates.rs"), code).unwrap();
}

/// Pull `value` out of a canonical `key = "value"` line (tolerating only
/// whitespace variations around `=`), or `None` if the line is not that key.
fn quoted_value(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    // Nothing may follow the closing quote (a trailing comment would be fine
    // for TOML but is not part of the canonical format the scripts write).
    inner[end + 1..]
        .trim()
        .is_empty()
        .then(|| inner[..end].to_string())
}

fn hex32(hex: &str, entry: usize, field: &str) -> [u8; 32] {
    assert_eq!(
        hex.len(),
        64,
        "legacy_delegates.toml entry {} has a {field} that is not 64 hex chars: `{hex}`",
        entry + 1
    );
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            panic!(
                "legacy_delegates.toml entry {} has a non-hex {field}: `{hex}`",
                entry + 1
            )
        });
    }
    out
}

fn hex_to_byte_array(hex: &str) -> String {
    let bytes: Vec<String> = (0..hex.len())
        .step_by(2)
        .map(|i| format!("0x{}", &hex[i..i + 2]))
        .collect();
    format!("[{}]", bytes.join(", "))
}
