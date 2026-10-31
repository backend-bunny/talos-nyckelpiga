#!/usr/bin/env bash
# Push the image built by hack/build.sh (same packages, same build lock) to
# $IMAGE under its tags and write the pushed index digest to out/digest. With
# DRY_RUN=1, only print the tags.
# Tags: <version> (releases only, PUBLISH_VERSION=1) and sha-<short commit>.
# Consumers pin by digest.
# Usage: hack/publish.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

[[ -f out/build.lock.json ]] || { echo "error: run hack/build.sh first" >&2; exit 1; }

refs=()
[[ -n ${PUBLISH_VERSION:-} ]] && refs+=("$IMAGE:$(version)")
refs+=("$IMAGE:sha-$(git rev-parse --short=7 HEAD)")

if [[ -n ${DRY_RUN:-} ]]; then
  printf 'would push %s\n' "${refs[@]}"
  exit 0
fi

# SBOMs come from hack/build.sh and are attached with cosign, not by apko.
mapfile -t annotations < <(version_annotation)
apko publish apko.yaml "${refs[@]}" \
  --arch "$(apko_archs)" --lockfile out/build.lock.json \
  --keyring-append out/melange.rsa.pub "${annotations[@]}" \
  --sbom=false --image-refs out/image-refs

# The tags point at an image index. apko's --image-refs lists the per-arch
# manifests inside it, so resolve the digest the tag actually points to:
# that is what consumers pin and what cosign must sign.
digest=$(docker buildx imagetools inspect "${refs[0]}" --format '{{json .Manifest}}' \
  | python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])')
if [[ $digest != sha256:* ]]; then
  echo "error: could not resolve the index digest of ${refs[0]}" >&2
  exit 1
fi
echo "$digest" > out/digest
echo "pushed $IMAGE@$digest"
