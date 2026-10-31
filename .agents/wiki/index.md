# Wiki Index

Operational knowledge for **backend-bunny/talos-nyckelpiga**. Read this
before troubleshooting; update it after every change (and add an entry at
the top of [log.md](log.md)).

## Components

| Page | Summary |
|------|---------|
| [components/kms-server.md](components/kms-server.md) | The server: protocol, request flow, allowlist, OpenBao auth/renewal, error → gRPC code mapping, TLS, reloads, zeroization, metrics, tests |
| [components/talos-kms-client.md](components/talos-kms-client.md) | How Talos v1.14.5 uses the KMS, from source: 32-byte key, lockToState, dialing (TLS roots, ALPN h2, timeouts), 30 s unseal retry, SMBIOS UUID |
| [components/helm-chart.md](components/helm-chart.md) | Helm chart: resources, hostPort vs TLSRoute passthrough, mounts and reloads, rollout, tests, OCI publish/sign |
| [components/build-pipeline.md](components/build-pipeline.md) | devbox, hack/ scripts, melange (Alpine, offline, static) + apko (Wolfi), lockfile, CI, release/sign, why no lock-refresh |

## Decisions

| Page | Summary |
|------|---------|
| [decisions/rust-tonic.md](decisions/rust-tonic.md) | Rust + tonic/prost, rustls with ring; approved crate set |
| [decisions/openbao-client-reqwest.md](decisions/openbao-client-reqwest.md) | Plain reqwest instead of vaultrs: exact status mapping, own trust store |
| [decisions/per-node-transit-keys.md](decisions/per-node-transit-keys.md) | One key per node, ciphertext verbatim, UUID as AAD, no auto-create |
| [decisions/tls-reload.md](decisions/tls-reload.md) | Reloading rustls cert resolver (polling) instead of exit-and-restart |
| [decisions/static-musl-alpine-build.md](decisions/static-musl-alpine-build.md) | Static musl via an Alpine melange env (Wolfi has no musl Rust; static glibc = LGPL) |
| [decisions/kubernetes-exposure.md](decisions/kubernetes-exposure.md) | hostPort on control planes by default; optional Gateway API TLS passthrough; no gateway TLS termination |
| [decisions/melange-apko-devbox.md](decisions/melange-apko-devbox.md) | Same as container-dropshipping, and what differs |
| [decisions/licensing.md](decisions/licensing.md) | Apache-2.0 repo, MPL-2.0 proto, crate notices attestation |

## Troubleshooting

| Page | Summary |
|------|---------|
| [troubleshooting/volume-wont-unseal.md](troubleshooting/volume-wont-unseal.md) | Audit log result/reason → cause → fix |
