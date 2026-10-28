#!/bin/bash
# Check that the published ghostkey-common (crates-io/ghostkey-common/) is the
# same crate as the frozen copy the delegate links (common/), apart from the
# two things that are meant to differ: the version and the freenet-stdlib
# requirement. See "Why two copies of ghostkey-common" in README.md.
#
# Source: byte-identical, every file under src/.
# Manifest: same edition, features, and dependencies (name, requirement, kind,
# optional, features, default-features), freenet-stdlib excluded.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! diff -r common/src crates-io/ghostkey-common/src; then
    echo "ERROR: common/src and crates-io/ghostkey-common/src differ. Edit both together." >&2
    exit 1
fi

FROZEN="$(cargo metadata --no-deps --format-version 1 --offline 2>/dev/null \
          || cargo metadata --no-deps --format-version 1)"
PUBLISHED="$(cd crates-io/ghostkey-common && { cargo metadata --no-deps --format-version 1 --offline 2>/dev/null \
          || cargo metadata --no-deps --format-version 1; })"

python3 -I - "$FROZEN" "$PUBLISHED" <<'PY'
import json, sys

def shape(meta):
    [pkg] = [p for p in json.loads(meta)["packages"] if p["name"] == "ghostkey-common"]
    deps = sorted(
        (d["name"], d["req"], d["kind"] or "normal", d["optional"],
         tuple(sorted(d["features"])), d["uses_default_features"])
        for d in pkg["dependencies"] if d["name"] != "freenet-stdlib"
    )
    feats = {k: sorted(v) for k, v in pkg["features"].items()}
    return {"edition": pkg["edition"], "features": feats, "dependencies": deps}

frozen, published = shape(sys.argv[1]), shape(sys.argv[2])
if frozen != published:
    for key in frozen:
        if frozen[key] != published[key]:
            print(f"ERROR: {key} differs\n  common/:                   {frozen[key]}\n"
                  f"  crates-io/ghostkey-common: {published[key]}", file=sys.stderr)
    sys.exit(1)
print("ghostkey-common: published crate matches the frozen copy (source and manifest)")
PY
