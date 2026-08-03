#!/bin/bash
# Build the delegate WASM the one canonical way.
#
# The delegate key is BLAKE3(BLAKE3(wasm) || params), so anything that changes
# a single byte of the WASM moves every user's secrets to a new namespace. That
# makes "which bytes does this source produce" a correctness question, not a
# build-hygiene nicety, and until now the answer depended on the machine.
#
# Two things were wrong (ghostkeys#9):
#
# 1. `Cargo.lock` was gitignored. Two checkouts of the same commit resolved
#    different dependency versions -- measured at 1699 differing lines between
#    the main checkout and a worktree -- and produced different delegate keys.
#    A stray `cargo update` was enough to silently orphan every user's
#    ghostkeys. Fixed by committing the lockfile; nothing in this script.
#
# 2. Dependency source paths are baked into the binary. `panic!` and friends
#    embed `file!()`, which for registry crates is an absolute path under
#    $CARGO_HOME. Measured: 50 such strings survive in the release WASM, all
#    from the registry, none from the workspace (workspace paths are already
#    relative). So the same source built on two machines with different $HOME
#    -- a developer's laptop and a CI runner -- produced different keys. That
#    is what made the old check-migration guard unsatisfiable, since CI could
#    never compute the hash a developer had recorded.
#
# Note `profile.release.strip = true` does NOT fix (2), despite a comment in
# Cargo.toml that used to claim it did. `strip` removes debug symbols; the
# panic-location strings are ordinary rodata and survive it untouched.
#
# `trim-paths` would be the tidy fix but is not stabilised in cargo 1.95, so
# this remaps by hand. The remap target is a fixed placeholder, identical
# everywhere, which is the whole point.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

# Appended, not assigned, so a caller's RUSTFLAGS still apply. Anyone who does
# set their own gets a different hash -- unavoidable, and their problem to
# know about; the canonical build is this script with nothing set.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$CARGO_HOME_DIR/registry/src=/cargo-registry"

cargo build --target wasm32-unknown-unknown --release -p ghostkey-delegate "$@"

WASM="target/wasm32-unknown-unknown/release/ghostkey_delegate.wasm"
if command -v b3sum >/dev/null 2>&1; then
    CODE_HASH="$(b3sum --no-names "$WASM")"
    echo "delegate code_hash:   $CODE_HASH"
    # Printed so a CI log and a local build can be compared by eye, which is
    # the only direct evidence that the reproducibility fix is still holding.
    if command -v xxd >/dev/null 2>&1; then
        echo "delegate key:         $(printf '%s' "$CODE_HASH" | xxd -r -p | b3sum --no-names)"
    fi
fi

# Fail loudly rather than silently shipping a machine-specific binary.
if command -v strings >/dev/null 2>&1; then
    LEAKED="$(strings "$WASM" | grep -c "$CARGO_HOME_DIR" || true)"
    if [ "$LEAKED" -ne 0 ]; then
        echo "ERROR: $LEAKED absolute path(s) from $CARGO_HOME_DIR are embedded in the WASM." >&2
        echo "The delegate key is therefore machine-specific: this build cannot be" >&2
        echo "reproduced elsewhere, and publishing it would move every user's secrets" >&2
        echo "to a namespace nobody else can recompute. See ghostkeys#9." >&2
        exit 1
    fi
fi
