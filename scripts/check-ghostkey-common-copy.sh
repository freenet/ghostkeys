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

# Listed first, on its own, so a git failure aborts (set -e) instead of
# yielding an empty list that passes.
TRACKED="$(git ls-files crates-io/ghostkey-common)"
[ -n "$TRACKED" ] || { echo "ERROR: git lists no files under crates-io/ghostkey-common" >&2; exit 1; }
EXTRA="$(printf '%s\n' "$TRACKED" \
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

python3 -I - "$FROZEN" "$PUBLISHED" "$REPO_ROOT" <<'PY'
import json, os, sys, tomllib

errors = []

# Things `cargo metadata` does not show, which would make CI build or test the
# crate differently from what `cargo publish` ships (a patched dependency, a
# changed profile) or change what ships (include/exclude). Parsed as TOML, so
# no spelling of the table header gets past.
root = sys.argv[3]
crate_dir = os.path.join(root, "crates-io", "ghostkey-common")
with open(os.path.join(crate_dir, "Cargo.toml"), "rb") as f:
    manifest = tomllib.load(f)
for key in ("patch", "replace", "profile", "lints"):
    if key in manifest or key in manifest.get("workspace", {}):
        errors.append(f"crates-io/ghostkey-common/Cargo.toml must not have [{key}]")
for key in ("include", "exclude", "build", "links", "workspace"):
    if key in manifest.get("package", {}):
        errors.append(f"crates-io/ghostkey-common/Cargo.toml must not set package.{key}")
# Cargo config applies from the crate's directory up to the filesystem root;
# the repository's part of that is checkable here.
d = crate_dir
while True:
    for name in ("config.toml", "config"):
        cfg = os.path.join(d, ".cargo", name)
        if os.path.isfile(cfg):
            with open(cfg, "rb") as f:
                config = tomllib.load(f)
            for key in ("patch", "source", "profile", "registries"):
                if key in config:
                    errors.append(f"{os.path.relpath(cfg, root)} sets [{key}], which would apply to the published crate's CI build")
    if os.path.samefile(d, root):
        break
    d = os.path.dirname(d)

def package(meta):
    [pkg] = [p for p in json.loads(meta)["packages"] if p["name"] == "ghostkey-common"]
    return pkg

def shape(pkg):
    deps = sorted(
        (d["name"],
         # freenet-stdlib's requirement is the one intended difference.
         "<stdlib range>" if d["name"] == "freenet-stdlib" else d["req"],
         d["kind"] or "normal", d["target"] or "", d["optional"],
         tuple(sorted(d["features"])), d["uses_default_features"],
         # A path or alternate source would be tested in CI and then stripped
         # or rewritten by `cargo publish`.
         d.get("source"), d.get("registry"), d.get("rename"),
         os.path.relpath(d["path"], os.path.dirname(pkg["manifest_path"])) if d.get("path") else None)
        for d in pkg["dependencies"]
    )
    targets = sorted(
        (t["name"], tuple(t["kind"]), tuple(t["crate_types"]), t["edition"],
         os.path.relpath(t["src_path"], os.path.dirname(pkg["manifest_path"])),
         # `test = false` would let the range tests pass with none run.
         t.get("test"), t.get("doctest"), t.get("doc"),
         tuple(t.get("required-features", [])))
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
    errors.append(f"common/ must stay ghostkey-common 0.3.0 with publish = false "
                  f"(the deployed delegate links exactly that); found version "
                  f"{frozen_pkg['version']}, publish {frozen_pkg['publish']}")

# The range is what the CI steps test (its floor and its newest release) and
# what README.md documents. Changing it is a deliberate act: update this too.
[stdlib] = [d for d in published_pkg["dependencies"] if d["name"] == "freenet-stdlib"]
if stdlib["req"] != ">=0.8, <0.13":
    errors.append(f"freenet-stdlib requirement is {stdlib['req']!r}; this check, the "
                  f"CI range steps and the crate README expect '>=0.8, <0.13'")

# Compared above, but also asserted: with `test = false` on BOTH sides the
# comparison passes and the range tests silently run nothing.
for t in published_pkg["targets"]:
    if "lib" in t["kind"] and not (t.get("test") and t.get("doctest")):
        errors.append("the published crate's lib target must keep test and doctest enabled")

frozen, published = shape(frozen_pkg), shape(published_pkg)
for key in frozen:
    if frozen[key] != published[key]:
        errors.append(f"{key} differs\n  common/:                   {frozen[key]}\n"
                      f"  crates-io/ghostkey-common: {published[key]}")
if errors:
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
print("ghostkey-common: published crate matches the frozen copy (source, files and manifest)")
PY
