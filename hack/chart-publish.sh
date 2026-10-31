#!/usr/bin/env bash
# Package the chart with the image digest just published (out/digest from
# hack/publish.sh) as its default, push it to oci://$REGISTRY/charts and
# write the chart's OCI digest to out/chart-digest. With DRY_RUN=1, package
# only. Expects `helm registry login` to have happened.
# Usage: hack/chart-publish.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

digest=${IMAGE_DIGEST:-$(cat out/digest 2>/dev/null || true)}
if [[ $digest != sha256:* ]]; then
  echo "error: no image digest (run hack/publish.sh first, or set IMAGE_DIGEST)" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -r charts/talos-nyckelpiga "$tmp/"
# The released chart pins the image it was released with.
python3 - "$tmp/talos-nyckelpiga/values.yaml" "$digest" <<'PY'
import sys
path, digest = sys.argv[1], sys.argv[2]
text = open(path).read()
old = '  digest: ""\n'
assert text.count(old) == 1, "image.digest line not found in values.yaml"
open(path, "w").write(text.replace(old, f'  digest: "{digest}"\n'))
PY
helm package "$tmp/talos-nyckelpiga" --destination out
pkg=out/talos-nyckelpiga-$(version).tgz

if [[ -n ${DRY_RUN:-} ]]; then
  echo "would push $pkg to oci://$REGISTRY/charts"
  exit 0
fi
helm push "$pkg" "oci://$REGISTRY/charts" 2>&1 | tee "$tmp/push.log"
chart_digest=$(sed -n 's/^Digest: //p' "$tmp/push.log")
if [[ $chart_digest != sha256:* ]]; then
  echo "error: could not read the pushed chart digest" >&2
  exit 1
fi
echo "$chart_digest" > out/chart-digest
echo "pushed $REGISTRY/charts/talos-nyckelpiga@$chart_digest"
