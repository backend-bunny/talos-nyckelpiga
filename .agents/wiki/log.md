# Wiki Log

Newest first. Format: `## [YYYY-MM-DD] <kind> | <subject>`.

## [2026-10-31] change | automated releases with release-please

- Maintainer chose a release-please PR over fully automatic releases or a
  local prepare script. `release-please.yml` maintains the release PR and,
  on merge, calls `release.yml` (now `workflow_call` + `workflow_dispatch`,
  no tag-push trigger) in the same run.
- Version markers (`# x-release-please-version`) in `melange.yaml` and
  `Chart.yaml`, so the YAML comments survive (release-please's yaml updater
  re-serialises files). Manifest starts at 0.0.0, so the first release PR
  proposes 0.1.0.
- Chart golden files hold `VERSION`; release bumps no longer touch them.
- `hack/check-commits.sh` + a `conventional-commits` CI job.
- First PR (initial server) was squash-merged as #1.

## [2026-10-31] add | Helm chart

- `charts/talos-nyckelpiga`: Deployment (hostPort, control planes, hard
  anti-affinity, maxSurge 0), config ConfigMap (checksum roll) + allowlist
  ConfigMap (hot reload, no roll), existing TLS Secret, projected SA token,
  optional OpenBao CA, Service, optional TLSRoute (passthrough),
  ServiceMonitor, NetworkPolicy, PDB, values schema. The brief listed "no
  Helm chart" as a non-goal; the maintainer asked for one.
- Server: `--check-config` validates config + allowlist without TLS or
  OpenBao; used by `hack/chart-test.sh` on every rendered config.
- Chart tests: lint, kubeconform (Kubernetes 1.37 + Gateway API v1.7
  TLSRoute v1 + ServiceMonitor schemas, pinned), golden files, invalid
  values. Release publishes the chart to GHCR (OCI) pinned to the image
  digest and signs it.
- Workflows under `.github/` can't be written from the sandboxed agent
  session; changes were staged in `ci-staging/` and moved by the maintainer.

## [2026-10-31] add | initial server, image pipeline, wiki

- Server: tonic `sidero.kms` Seal/Unseal → OpenBao transit encrypt/decrypt,
  one key per node, UUID as AAD, allowlist before OpenBao (hot reload), TLS
  cert reload via resolver, Kubernetes/token auth with renewal and 403
  re-login, JSON audit log, `/healthz` `/readyz` `/metrics`.
- Verified Talos v1.14.5 behaviour from source (32-byte key; lockToState is
  local; ALPN h2 enforced; unseal retried every 30 s, codes ignored; SMBIOS
  UUID lowercase). See [[components/talos-kms-client]].
- Verified OpenBao v2.7.2: AAD works on AEAD keys without `derived`; deleted
  key → 400 "encryption key not found"; sealed → 503; `update`-only policy
  can't auto-create keys.
- Upstream `kms.proto` has no license header: vendored unchanged with an
  added MPL-2.0 header (brief assumed one existed).
- Static musl: Wolfi has no musl Rust, and static glibc would pull in LGPL,
  so melange builds in Alpine v3.24 (maintainer's suggestion); runtime stays
  Wolfi. Crates vendored on the host; the melange build is offline.
- No lock-refresh workflow: the runtime lock is baselayout + CA bundle only,
  and publishing is tag-only.
