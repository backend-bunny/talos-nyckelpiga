#!/usr/bin/env bash
# Load out/image.tar into Docker and smoke-test it: numeric non-root user,
# OCI labels, --version, then a real run with a throwaway self-signed cert:
# health endpoints, and a gRPC Seal over TLS (h2) for a node that isn't
# allowlisted, which must be refused without OpenBao (none is running).
# Usage: hack/test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

# apko may suffix the tag (e.g. ":build-amd64"), so use the name docker reports.
image=$(docker load --input out/image.tar | sed -n 's/^Loaded image: //p' | head -n1)
if [[ -z $image ]]; then
  echo "FAIL: docker load reported no image for out/image.tar" >&2
  exit 1
fi
echo "testing $image"

# Must run as the numeric non-root UID (restricted Pod Security).
user=$(docker image inspect --format '{{.Config.User}}' "$image")
if [[ $user != 65532 && $user != 65532:65532 ]]; then
  echo "FAIL: image user is '$user', want 65532" >&2
  exit 1
fi

# Standard OCI annotations, which apko also writes as config labels.
labels=$(docker image inspect --format '{{json .Config.Labels}}' "$image")
for key in title description licenses url version; do
  if ! jq -e --arg k "org.opencontainers.image.$key" '.[$k] // "" | length > 0' \
    <<<"$labels" >/dev/null; then
    echo "FAIL: missing label org.opencontainers.image.$key (set it in apko.yaml annotations)" >&2
    exit 1
  fi
done

got=$(docker run --rm "$image" --version)
if [[ $got != "talos-nyckelpiga $(version)" ]]; then
  echo "FAIL: --version printed '$got'" >&2
  exit 1
fi

# Distroless: no shell.
if docker run --rm --entrypoint /bin/sh "$image" -c true 2>/dev/null; then
  echo "FAIL: image has a shell" >&2
  exit 1
fi

tmp=$(mktemp -d)
name=nyckelpiga-smoke-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
cargo run --quiet --locked --example selfsigned -- "$tmp"
cat > "$tmp/config.toml" <<'TOML'
[server]
tls_cert = "/config/tls.crt"
tls_key = "/config/tls.key"
[openbao]
address = "http://127.0.0.1:1"
[openbao.auth]
method = "token"
token_path = "/config/missing-token"
[allowlist]
path = "/config/allowlist.toml"
TOML
printf '[[node]]\nuuid = "4c4c4544-0042-3510-8051-b4c04f4e3732"\n' > "$tmp/allowlist.toml"
chmod -R a+rX "$tmp"

docker run -d --name "$name" -v "$tmp:/config:ro" -p 127.0.0.1::4050 -p 127.0.0.1::8080 \
  "$image" --config /config/config.toml >/dev/null
grpc=$(docker port "$name" 4050/tcp | head -n1)
health=$(docker port "$name" 8080/tcp | head -n1)

for _ in $(seq 50); do
  curl -fsS "http://$health/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "http://$health/healthz" >/dev/null || { docker logs "$name"; echo "FAIL: /healthz" >&2; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' "http://$health/readyz")
[[ $code == 503 ]] || { echo "FAIL: /readyz is $code without OpenBao, want 503" >&2; exit 1; }

out=$(grpcurl -cacert "$tmp/tls.crt" -authority localhost -import-path proto -proto kms.proto \
  -d '{"node_uuid":"00000000-0000-0000-0000-00000000dead","data":"AAAA"}' \
  "$grpc" sidero.kms.KMSService/Seal 2>&1 || true)
if ! grep -q 'Code: PermissionDenied' <<<"$out"; then
  docker logs "$name"
  echo "FAIL: Seal for an unknown node: $out" >&2
  exit 1
fi
# The refusal is audit-logged as JSON.
# (Field order in the JSON isn't fixed, so match with jq, not grep.)
docker logs "$name" 2>&1 \
  | jq -R -s -e '[split("\n")[] | fromjson? | select(.target == "audit" and .result == "permission_denied")] | length > 0' >/dev/null \
  || { docker logs "$name"; echo "FAIL: no audit event" >&2; exit 1; }

echo "PASS: talos-nyckelpiga"
