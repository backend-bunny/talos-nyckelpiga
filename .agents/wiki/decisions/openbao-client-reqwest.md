---
title: OpenBao client — plain reqwest, not vaultrs
category: decision
tags: [openbao, reqwest, vaultrs]
date: 2026-11-06
---

# OpenBao client: plain reqwest

## Decision

Talk to the OpenBao HTTP API with `reqwest` 0.13 (`rustls-no-provider` +
our own rustls `ClientConfig` with ring, `tls_backend_preconfigured`).
No `json` feature: bodies are serialised with serde_json.

HTTP is allowed with a prominent startup warning; the configured URL is never
included in that warning. All redirects are disabled, including same-origin
redirects. Reqwest's automatic redirect policy can forward `X-Vault-Token` and
POST bodies to another origin or downgrade HTTPS to HTTP. Redirect responses
return `UNAVAILABLE` without exposing their Location or body. Deployments must
configure an endpoint that directly serves OpenBao requests.

The custom CA bundle replaces system roots. The selected file (custom bundle,
`SSL_CERT_FILE` or system bundle) is loaded at startup and polled with the
existing `FileWatch` at `server.reload_interval_secs`. Reopening its path each
tick follows Kubernetes' `..data` symlink swaps without an inode watch or a new
dependency. Multiple PEM blocks allow old+new root overlap during rotation.

A reload builds and validates a complete replacement client before publishing
it through `ArcSwap`. It also replaces the connection pool and TLS session
cache: new requests must not reuse a connection authenticated by a removed
root. In-flight requests can finish with the old client. Invalid updates keep
the previous client, emit an error and increment `openbao_ca_reloads_total`,
then retry next tick. Tokens are retained; changing trust does not force login.

## Why

- Four endpoints: `auth/<mount>/login`, `auth/token/renew-self`,
  `auth/token/lookup-self`, `<transit>/encrypt|decrypt/<key>`.
- The gRPC mapping depends on the exact HTTP status and OpenBao's error
  string (503 sealed vs 403 vs 400 "encryption key not found"). vaultrs wraps
  errors through rustify, which makes that coarser.
- We control the trust store (private CA only, or the system bundle) and
  timeouts directly, and keep response bodies in `Zeroizing` buffers.
- Login/transit request structs borrow secrets from `Zeroizing` owners so
  cancellation cannot skip cleanup of a separate JSON string copy.
- Fewer transitive dependencies.

## Consequences

We maintain the request/response structs ourselves. They're covered by the
integration test against a real `bao server -dev`, so API drift shows up there.
