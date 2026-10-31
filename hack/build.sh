#!/usr/bin/env bash
# Build the image exactly as CI does:
#   ephemeral melange key -> melange build + test -> apko build from the lock.
# Outputs out/{image.tar,build.lock.json,sbom-*.spdx.json,notices.{json,md},melange.rsa.pub}.
# Usage: hack/build.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

hack/check-version.sh
if [[ ! -f apko.lock.json ]]; then
  echo "error: apko.lock.json is missing; run: task lock" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rm -rf out && mkdir -p out

echo "::group::melange build + test"
build_package "$tmp" out/melange.rsa.pub
echo "::endgroup::"

echo "::group::resolve + check lock"
fresh_lock out/melange.rsa.pub "$tmp/fresh.lock.json"
python3 hack/lockfile.py merge apko.lock.json "$tmp/fresh.lock.json" apko.yaml out/build.lock.json
echo "::endgroup::"

echo "::group::apko build"
mapfile -t annotations < <(version_annotation)
apko build apko.yaml "$IMAGE:build" out/image.tar \
  --arch "$(apko_archs)" --lockfile out/build.lock.json \
  --keyring-append out/melange.rsa.pub "${annotations[@]}" \
  --sbom-path out
echo "::endgroup::"

echo "::group::license notices"
# Licenses and notice files of every Rust crate in the binary.
python3 hack/notices.py out/notices.json out/notices.md
echo "::endgroup::"

echo "built out/image.tar"
