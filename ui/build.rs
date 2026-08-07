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

    let mut entries = Vec::new();

    // Simple TOML parsing for [[entry]] blocks
    let mut current_delegate_key = None;
    let mut current_code_hash = None;

    for line in content.lines() {
        let line = line.trim();
        if line == "[[entry]]" {
            if let (Some(dk), Some(ch)) = (current_delegate_key.take(), current_code_hash.take()) {
                entries.push((dk, ch));
            }
        } else if let Some(val) = line.strip_prefix("delegate_key = \"") {
            current_delegate_key = Some(val.trim_end_matches('"').to_string());
        } else if let Some(val) = line.strip_prefix("code_hash = \"") {
            current_code_hash = Some(val.trim_end_matches('"').to_string());
        }
    }
    if let (Some(dk), Some(ch)) = (current_delegate_key, current_code_hash) {
        entries.push((dk, ch));
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

fn hex_to_byte_array(hex: &str) -> String {
    let bytes: Vec<String> = (0..hex.len())
        .step_by(2)
        .map(|i| format!("0x{}", &hex[i..i + 2]))
        .collect();
    format!("[{}]", bytes.join(", "))
}
