---
title: OpenBao client — plain reqwest, not vaultrs
category: decision
tags: [openbao, reqwest, vaultrs]
date: 2026-10-31
---

# OpenBao client: plain reqwest

## Decision

Talk to the OpenBao HTTP API with `reqwest` 0.13 (`rustls-no-provider` +
our own rustls `ClientConfig` with ring, `tls_backend_preconfigured`).
No `json` feature: bodies are serialised with serde_json.

## Why

- Four endpoints: `auth/<mount>/login`, `auth/token/renew-self`,
  `auth/token/lookup-self`, `<transit>/encrypt|decrypt/<key>`.
- The gRPC mapping depends on the exact HTTP status and OpenBao's error
  string (503 sealed vs 403 vs 400 "encryption key not found"). vaultrs wraps
  errors through rustify, which makes that coarser.
- We control the trust store (private CA only, or the system bundle) and
  timeouts directly, and keep response bodies in `Zeroizing` buffers.
- Fewer transitive dependencies.

## Consequences

We maintain the request/response structs ourselves. They're covered by the
integration test against a real `bao server -dev`, so API drift shows up there.
