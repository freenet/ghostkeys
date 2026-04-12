use std::process::Command;

fn main() {
    // Always re-run to keep timestamp fresh
    println!("cargo:rerun-if-changed=build.rs");

    let now = chrono::Utc::now();
    let build_timestamp_iso = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    println!("cargo:rustc-env=BUILD_TIMESTAMP_ISO={build_timestamp_iso}");

    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_COMMIT={git_hash}");
}
