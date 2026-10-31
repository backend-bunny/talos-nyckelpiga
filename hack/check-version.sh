#!/usr/bin/env bash
# Fail unless melange.yaml's version equals Cargo.toml's and, when given a
# release tag (vX.Y.Z), the tag too.
# Usage: hack/check-version.sh [tag]
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

melange=$(version)
cargo=$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml)
if [[ $melange != "$cargo" ]]; then
  echo "error: melange.yaml version $melange != Cargo.toml version $cargo" >&2
  exit 1
fi
if [[ -n ${1:-} && $1 != "v$cargo" ]]; then
  echo "error: tag $1 doesn't match version $cargo (expected v$cargo)" >&2
  exit 1
fi
echo "version $cargo"
