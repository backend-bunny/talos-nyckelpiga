#!/usr/bin/env bash
# Test the Helm chart, as CI does. For each charts/talos-nyckelpiga/ci/*-values.yaml:
#   helm lint --strict; helm template | kubeconform -strict (Kubernetes
#   schemas plus the Gateway API / Prometheus Operator CRDs, both pinned);
#   compare with the golden file in tests/ (UPDATE_GOLDEN=1 rewrites it);
#   and run the rendered config.toml + allowlist.toml through the server's
#   own parser (talos-nyckelpiga --check-config).
# Then check that invalid values fail to render.
# Usage: hack/chart-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

chart=charts/talos-nyckelpiga
k8s_version=1.37.0
# Pinned schema sources (bump deliberately).
k8s_schemas=https://raw.githubusercontent.com/yannh/kubernetes-json-schema/e0c72a1bc5f409d1685c0e1323460c8a98cd7459
crd_schemas=https://raw.githubusercontent.com/datreeio/CRDs-catalog/3eb90d47aba8d61919d4419dd38301536e32a94b

version=$(awk '/^version:/ { print $2; exit }' "$chart/Chart.yaml")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cargo build --quiet --locked
bin=target/debug/talos-nyckelpiga

render() {
  helm template kms "$chart" --namespace kms "$@"
}

# Print the block scalar under `  <key>: |` from rendered YAML on stdin.
extract() {
  python3 -c '
import sys, textwrap
key, lines, out, inside = sys.argv[1], sys.stdin.read().splitlines(), [], False
for line in lines:
    if inside:
        if line.strip() and not line.startswith("    "):
            break
        out.append(line)
    elif line == f"  {key}: |":
        inside = True
print(textwrap.dedent("\n".join(out)))
' "$1"
}

failed=0
for values in "$chart"/ci/*-values.yaml; do
  name=$(basename "$values" -values.yaml)
  echo "== $name"
  helm lint --strict --quiet "$chart" -f "$values"
  render -f "$values" > "$tmp/$name.yaml"

  kubeconform -strict -summary -kubernetes-version "$k8s_version" \
    -schema-location "$k8s_schemas/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json" \
    -schema-location "$crd_schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
    "$tmp/$name.yaml"

  # Golden files hold VERSION instead of the chart version, so release-please
  # bumps (which don't regenerate them) don't break the comparison.
  golden=$chart/tests/$name.golden.yaml
  sed "s/${version//./\\.}/VERSION/g" "$tmp/$name.yaml" > "$tmp/$name.normalized.yaml"
  if [[ -n ${UPDATE_GOLDEN:-} ]]; then
    cp "$tmp/$name.normalized.yaml" "$golden"
  elif ! diff -u "$golden" "$tmp/$name.normalized.yaml"; then
    echo "FAIL: $name differs from $golden (UPDATE_GOLDEN=1 hack/chart-test.sh to accept)" >&2
    failed=1
  fi

  # Value sets without hostPort must fit Pod Security `restricted`: no host
  # ports or namespaces, no privileged containers (the securityContext fields
  # restricted requires are pinned by the golden files).
  if grep -q 'enabled: false' <(sed -n '/^grpc:/,/^[a-z]/p' "$values"); then
    if grep -nE 'hostPort:|hostNetwork:|hostPID:|hostIPC:|hostPath:|privileged: true' "$tmp/$name.yaml"; then
      echo "FAIL: $name has hostPort off but renders host access" >&2
      failed=1
    else
      echo "no host access (restricted-compatible)"
    fi
  fi

  extract config.toml < "$tmp/$name.yaml" > "$tmp/$name.config.toml"
  allowlist=$tmp/$name.allowlist.toml
  extract allowlist.toml < "$tmp/$name.yaml" > "$allowlist"
  # An existing allowlist ConfigMap isn't rendered; check the config alone.
  [[ -s $allowlist ]] && grep -q uuid "$allowlist" || allowlist=examples/allowlist.toml
  NYCKELPIGA_ALLOWLIST__PATH="$allowlist" RUST_LOG=warn \
    "$bin" --config "$tmp/$name.config.toml" --check-config
  echo "config and allowlist accepted by the server"
done

# Values that must not render.
must_fail() {
  local why=$1
  shift
  if render "$@" >/dev/null 2>"$tmp/err"; then
    echo "FAIL: rendered despite $why" >&2
    failed=1
  else
    echo "ok: refused $why ($(head -n1 "$tmp/err" | cut -c1-100))"
  fi
}
min=(-f "$chart/ci/minimal-values.yaml")
must_fail "no values at all"
must_fail "an invalid node UUID" "${min[@]}" --set 'allowlist.nodes[0].uuid=not-a-uuid'
must_fail "an empty allowlist" "${min[@]}" --set 'allowlist.nodes=null'
must_fail "a non-sha256 digest" "${min[@]}" --set image.digest=latest
must_fail "a key template without {uuid}" "${min[@]}" --set openbao.keyTemplate=static
must_fail "a TLSRoute without hostnames" "${min[@]}" --set tlsRoute.enabled=true \
  --set 'tlsRoute.parentRefs[0].name=gw'
must_fail "two OpenBao CA sources" "${min[@]}" --set openbao.caCert.configMap=a \
  --set openbao.caCert.secret=b
must_fail "a missing TLS secret" "${min[@]}" --set tls.secretName=
must_fail "an unknown anti-affinity mode" "${min[@]}" --set podAntiAffinity=maybe
must_fail "an unknown Service type" "${min[@]}" --set service.type=ExternalName
must_fail "a nodePort on a ClusterIP Service" "${min[@]}" --set service.nodePort=30450
must_fail "a nodePort outside 30000-32767" "${min[@]}" --set service.type=NodePort --set service.nodePort=4050
must_fail "load balancer source ranges without LoadBalancer" "${min[@]}" \
  --set 'service.loadBalancerSourceRanges[0]=10.0.0.0/8'
must_fail "a surge with hostPort" "${min[@]}" --set rollingUpdate.maxSurge=1 --set rollingUpdate.maxUnavailable=0

exit "$failed"
