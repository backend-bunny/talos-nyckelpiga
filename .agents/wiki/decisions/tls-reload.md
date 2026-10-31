---
title: TLS certificate reload via a rustls cert resolver
category: decision
tags: [tls, rustls, cert-manager]
date: 2026-10-31
---

# TLS reload: resolver, not restart

## Context

The listener needs a publicly trusted certificate (Talos can't take a custom
CA for the KMS), e.g. Let's Encrypt from cert-manager, renewed about every
60 days and mounted from a Secret.

## Decision

A `rustls::server::ResolvesServerCert` holding the current `CertifiedKey` in
an `ArcSwap`. A task re-reads `tls.crt` + `tls.key` every
`reload_interval_secs` (default 30), compares a hash of both, and swaps in
the new pair only if it parses and `keys_match()`. Otherwise it keeps the
old pair, logs an error, counts `tls_reloads_total{result="error"}` and
retries every tick.

## Why not exit-and-restart

- No restart window. On control-plane `hostPort` pods a restart briefly
  drops the KMS while nodes may be booting (Talos retries, but still).
- A broken renewal (cert and key written separately, a bad issuer) doesn't
  crash-loop the pod: the old, still-valid certificate keeps being served.
- Polling contents instead of inotify works with Kubernetes' atomic
  `..data` symlink swap.

Existing connections keep their session; Talos opens a new connection per
call anyway. Covered by `tls_certificate_reload` in the integration test and
by a unit test for the mismatched-pair case.
