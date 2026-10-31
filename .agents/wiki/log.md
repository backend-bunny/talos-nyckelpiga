# Wiki Log

Newest first. Format: `## [YYYY-MM-DD] <kind> | <subject>`.

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
