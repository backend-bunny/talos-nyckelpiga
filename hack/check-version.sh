#!/usr/bin/env bash
# Fail unless melange.yaml's version and the chart's version and appVersion
# equal Cargo.toml's and, when given a release tag (vX.Y.Z), the tag too.
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
chart=charts/talos-nyckelpiga/Chart.yaml
chart_version=$(awk '/^version:/ { print $2; exit }' "$chart")
app_version=$(awk -F'"' '/^appVersion:/ { print $2; exit }' "$chart")
if [[ $chart_version != "$cargo" || $app_version != "$cargo" ]]; then
  echo "error: $chart version $chart_version / appVersion $app_version != Cargo.toml version $cargo" >&2
  exit 1
fi
if [[ -n ${1:-} && $1 != "v$cargo" ]]; then
  echo "error: tag $1 doesn't match version $cargo (expected v$cargo)" >&2
  exit 1
fi
echo "version $cargo"
