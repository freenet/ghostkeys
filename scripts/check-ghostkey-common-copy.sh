#!/bin/bash
# Check that the published ghostkey-common (crates-io/ghostkey-common/) is the
# same crate as the frozen copy the delegate links (common/), apart from the
# two things that are meant to differ: the version and the freenet-stdlib
# requirement. See "Why two copies of ghostkey-common" in README.md.
#
# Source: byte-identical, every file under src/, and no other tracked file in
# the published crate beyond its manifest, lockfile, README and .gitignore (so
# nothing like a build.rs or an include!-ed data file can differ unseen).
# Manifest: same package metadata, targets, features and dependencies (name,
# requirement, kind, target, optional, features, default-features). The ONE
# exception is freenet-stdlib's version requirement; its other settings must
# match too. The frozen copy must also still be version 0.3.0, publish = false.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! diff -r common/src crates-io/ghostkey-common/src; then
    echo "ERROR: common/src and crates-io/ghostkey-common/src differ. Edit both together." >&2
    exit 1
fi

EXTRA="$(git ls-files crates-io/ghostkey-common \
         | grep -v -x -e 'crates-io/ghostkey-common/Cargo.toml' \
                      -e 'crates-io/ghostkey-common/Cargo.lock' \
                      -e 'crates-io/ghostkey-common/README.md' \
                      -e 'crates-io/ghostkey-common/.gitignore' \
                      -e 'crates-io/ghostkey-common/src/.*' || true)"
if [ -n "$EXTRA" ]; then
    echo "ERROR: unexpected file(s) in the published crate, with no counterpart check:" >&2
    echo "$EXTRA" >&2
    exit 1
fi

FROZEN="$(cargo metadata --no-deps --format-version 1 --offline 2>/dev/null \
          || cargo metadata --no-deps --format-version 1)"
PUBLISHED="$(cd crates-io/ghostkey-common && { cargo metadata --no-deps --format-version 1 --offline 2>/dev/null \
          || cargo metadata --no-deps --format-version 1; })"

python3 -I - "$FROZEN" "$PUBLISHED" <<'PY'
import json, sys

import os

def package(meta):
    [pkg] = [p for p in json.loads(meta)["packages"] if p["name"] == "ghostkey-common"]
    return pkg

def shape(pkg):
    deps = sorted(
        (d["name"],
         # freenet-stdlib's requirement is the one intended difference.
         "<stdlib range>" if d["name"] == "freenet-stdlib" else d["req"],
         d["kind"] or "normal", d["target"] or "", d["optional"],
         tuple(sorted(d["features"])), d["uses_default_features"])
        for d in pkg["dependencies"]
    )
    targets = sorted(
        (t["name"], tuple(t["kind"]), tuple(t["crate_types"]), t["edition"],
         os.path.relpath(t["src_path"], os.path.dirname(pkg["manifest_path"])))
        for t in pkg["targets"]
    )
    meta = {k: pkg.get(k) for k in (
        "edition", "description", "license", "license_file", "repository",
        "homepage", "documentation", "readme", "keywords", "categories",
        "rust_version", "links")}
    meta["features"] = {k: sorted(v) for k, v in pkg["features"].items()}
    meta["targets"] = targets
    meta["dependencies"] = deps
    return meta

frozen_pkg, published_pkg = package(sys.argv[1]), package(sys.argv[2])
if frozen_pkg["version"] != "0.3.0" or frozen_pkg["publish"] != []:
    print(f"ERROR: common/ must stay ghostkey-common 0.3.0 with publish = false "
          f"(the deployed delegate links exactly that); found version "
          f"{frozen_pkg['version']}, publish {frozen_pkg['publish']}", file=sys.stderr)
    sys.exit(1)
frozen, published = shape(frozen_pkg), shape(published_pkg)
if frozen != published:
    for key in frozen:
        if frozen[key] != published[key]:
            print(f"ERROR: {key} differs\n  common/:                   {frozen[key]}\n"
                  f"  crates-io/ghostkey-common: {published[key]}", file=sys.stderr)
    sys.exit(1)
print("ghostkey-common: published crate matches the frozen copy (source, files and manifest)")
PY
