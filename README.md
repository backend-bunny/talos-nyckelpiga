# talos-nyckelpiga

Talos Linux KMS server backed by OpenBao/Vault transit: per-node, revocable
keys for LUKS-encrypted Talos volumes.

*Nyckelpiga* is Swedish for ladybug; *nyckel* means key.

## What it does

Talos can encrypt a volume with LUKS2 using a `kms` key slot. When it
provisions the volume, Talos generates a random 32-byte key, sends it to a
network KMS (`Seal`) and stores the returned blob in the LUKS2 header. On
every boot it sends the blob back (`Unseal`) to get the key.

talos-nyckelpiga answers those gRPC calls with OpenBao transit:

| Talos call | OpenBao request | Returned to Talos |
|---|---|---|
| `Seal(node_uuid, key)` | `transit/encrypt/talos-kms-<uuid>` | transit's ciphertext string, verbatim (`vault:v1:…`) |
| `Unseal(node_uuid, blob)` | `transit/decrypt/talos-kms-<uuid>` | the original key |

- **One transit key per node.** Deleting a node's key revokes it: its disks
  can never be unsealed again. Transit key rotation keeps working, because the
  stored blob names its key version.
- **Bound to the node.** The node UUID is sent as transit `associated_data`
  (AES-GCM), so a blob only decrypts for the node that sealed it.
- **Allowlist before OpenBao.** Unknown UUIDs get `PERMISSION_DENIED` and
  cause no OpenBao request. The allowlist file is reloaded on change.
- **Audit log.** One JSON event per call (node UUID, label, peer, result,
  latency). Keys, plaintexts and ciphertexts are never logged.
- **No key storage here.** OpenBao is the only key holder; there is no
  static or break-glass key path.

The KMS protocol has no client authentication. Anyone who can reach the
endpoint, knows a node UUID and has that node's LUKS header can unseal it.
Keep the endpoint on a private network, and rely on the allowlist, per-node
keys, the audit log and revocation.

## Runtime contract

- Talos dials `https://kms.example.com:4050` with grpc-go: TLS verified
  against Talos's trusted roots, ALPN `h2`. **Talos can't be given a custom
  CA for the KMS endpoint**, so the server needs a publicly trusted
  certificate (e.g. Let's Encrypt via cert-manager, mounted from a
  `kubernetes.io/tls` Secret). Renewed certificates are picked up without a
  restart.
- OpenBao is reached over HTTPS with its own (possibly private) CA, and the
  server logs in with the Kubernetes auth method using its projected
  service-account token.
- Health and metrics on a separate plain-HTTP port: `/healthz` (process up),
  `/readyz` (holds an OpenBao token), `/metrics` (Prometheus).

### What OpenBao must provide

Created outside this repo (e.g. with OpenTofu):

```hcl
# Transit mount (default path "transit") with one key per node:
#   transit/keys/talos-kms-<node-uuid>   type aes256-gcm96 (the default)
# Deleting a key revokes the node; it needs deletion_allowed=true first.

# Policy for the server: update only. Without `create`, encrypt can't
# auto-create a key for a node that has none.
path "transit/encrypt/talos-kms-*" { capabilities = ["update"] }
path "transit/decrypt/talos-kms-*" { capabilities = ["update"] }
```

Plus a Kubernetes auth role bound to the server's service account with that
policy. Optionally set `transit/config/keys disable_upsert=true` as a second
guard against key auto-creation.

The node UUID is the SMBIOS system UUID Talos reports, lowercase:

```sh
talosctl -n <node> get systeminformation -o jsonpath='{.spec.uuid}'
```

## Configuration

One TOML file (`--config`, default `/etc/talos-nyckelpiga/config.toml`, or
`$NYCKELPIGA_CONFIG`). Any key can be overridden from the environment as
`NYCKELPIGA_<TABLE>__<KEY>`, e.g. `NYCKELPIGA_OPENBAO__ADDRESS`. Unknown keys
are errors.

| Key | Default | |
|---|---|---|
| `server.listen` | `0.0.0.0:4050` | gRPC over TLS |
| `server.tls_cert`, `server.tls_key` | (required) | PEM files, re-read on change |
| `server.reload_interval_secs` | `30` | how often cert and allowlist are checked |
| `health.listen` | `0.0.0.0:8080` | plain HTTP: `/healthz`, `/readyz`, `/metrics` |
| `openbao.address` | (required) | e.g. `https://openbao.openbao.svc:8200` |
| `openbao.ca_cert` | system bundle | PEM CA bundle trusted *instead of* the system roots |
| `openbao.transit_mount` | `transit` | |
| `openbao.key_template` | `talos-kms-{uuid}` | transit key name per node |
| `openbao.associated_data` | `true` | bind blobs to the node UUID |
| `openbao.request_timeout_secs` | `5` | per OpenBao request (Talos allows 10 s per call) |
| `openbao.auth.method` | (required) | `kubernetes` or `token` |
| `openbao.auth.mount` | `kubernetes` | kubernetes: auth mount path |
| `openbao.auth.role` | (required) | kubernetes: role name |
| `openbao.auth.token_path` | SA token path | kubernetes: JWT file; token: OpenBao token file |
| `allowlist.path` | (required) | allowlist TOML, re-read on change |

Examples: [`examples/config.toml`](examples/config.toml),
[`examples/allowlist.toml`](examples/allowlist.toml). The allowlist:

```toml
[[node]]
uuid = "4c4c4544-0042-3510-8051-b4c04f4e3732"
label = "worker-1"   # optional, shown in logs
```

`token` auth reads an OpenBao token from a file (for example an OpenBao
Agent sink) and re-reads it when OpenBao rejects it. It is for tests and
non-Kubernetes setups.

`talos-nyckelpiga --config <file> --check-config` validates the config
(including env overrides) and the allowlist it points to, then exits. It
needs neither the TLS files nor OpenBao.

Logs are JSON on stderr; `RUST_LOG` sets the level (default `info`).

### Failure behaviour

Talos ignores gRPC status codes: any failed `Unseal` is retried by its
volume controller every 30 seconds, without limit. A sealed or unreachable
OpenBao therefore heals on its own once OpenBao is back. A revoked node
keeps retrying (and failing) until it is reset. Codes are still mapped for
operators:

| Situation | gRPC code |
|---|---|
| node UUID malformed, empty or oversized data, not a transit ciphertext, wrong node or tampered blob | `INVALID_ARGUMENT` |
| node not in the allowlist; OpenBao policy denies the key | `PERMISSION_DENIED` |
| node's transit key deleted (revoked) | `NOT_FOUND` |
| OpenBao sealed, unreachable, timing out, rate-limiting, 5xx; no token yet | `UNAVAILABLE` |

## Kubernetes (Helm)

`oci://ghcr.io/backend-bunny/charts/talos-nyckelpiga`, released with each
image and defaulting to that image's digest. It covers hostPort on the
control planes (the default) or a Gateway API TLSRoute with passthrough, an
existing TLS Secret, a projected service-account token for OpenBao, the
allowlist as a hot-reloaded ConfigMap, a PDB, and an optional ServiceMonitor
and NetworkPolicy. See [`charts/talos-nyckelpiga/README.md`](charts/talos-nyckelpiga/README.md).

## Image

`ghcr.io/backend-bunny/talos-nyckelpiga`, built with melange + apko (no
Dockerfile): a fully static binary on a distroless Wolfi base, running as
UID 65532, with no shell or package manager.

- Tags: the release version (e.g. `0.1.0`) and an immutable `sha-<short>`.
  **Pin by digest.**
- Every published index digest is signed keylessly with cosign (GitHub
  OIDC), with SPDX SBOM, build provenance and crate license notices as
  attestations:

```sh
cosign verify ghcr.io/backend-bunny/talos-nyckelpiga@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/backend-bunny/talos-nyckelpiga/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The container needs the TLS Secret, the config and the allowlist mounted,
and a projected service-account token. Example ports: `4050` (gRPC, e.g.
as a `hostPort`) and `8080` (probes and metrics).

## Development

Tools come from [devbox](https://www.jetify.com/devbox) (`devbox shell`, or
direnv with the committed `.envrc`).

```sh
task check          # fmt, clippy -D warnings, unit + OpenBao integration tests
task chart          # helm lint, kubeconform, golden files, config check
task image:test     # melange + apko build, then a Docker smoke test
task lock           # regenerate apko.lock.json
```

The integration tests start a real `bao server -dev`.

### Releases

Automated with [release-please](https://github.com/googleapis/release-please).
PR titles and commit subjects must be
[Conventional Commits](https://www.conventionalcommits.org/) (CI checks):
`feat:` bumps the minor version (while < 1.0), `fix:`/`perf:`/`deps:` the
patch, and `!` marks a breaking change.

1. Every merge to `main` updates one open **`chore: release X.Y.Z`** PR. It
   carries the next version in `Cargo.toml`/`Cargo.lock`, `melange.yaml` and
   the chart, plus the `CHANGELOG.md` entry. Don't bump versions by hand.
2. Merge it when you want to ship. That tags `vX.Y.Z`, creates the GitHub
   Release, and publishes and signs the image and the chart. The digests and
   `cosign verify` commands are appended to the release notes.
3. To pick up newer Wolfi CA certificates, merge a `build: task lock` PR
   first.

## License

Apache-2.0 (`LICENSE`), except `proto/kms.proto`, which is vendored from
[siderolabs/kms-client](https://github.com/siderolabs/kms-client) and is
MPL-2.0. The image contains Rust crates under permissive licenses (MIT,
Apache-2.0, ISC, BSD-3-Clause, Unicode-3.0, Unlicense). Their license texts
are in the notices attestation on each image. Wolfi's base packages are
listed in the SBOM attestation.
