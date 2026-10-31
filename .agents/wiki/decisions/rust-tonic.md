---
title: Rust with tonic/prost
category: decision
tags: [rust, grpc, tonic]
date: 2026-10-31
---

# Rust with tonic/prost

## Context

A small, security-sensitive network service holding plaintext keys in
memory for one request at a time, shipped as a minimal image.

## Decision

Rust, `tonic` 0.14 + `prost` (codegen with `tonic-prost-build`, protoc from
devbox / the build environment), tokio, rustls with the **ring** provider
everywhere (reqwest, server TLS). That avoids aws-lc-rs's cmake/C toolchain
in the static musl build.

## Why

- Memory safety, `zeroize` for owned secrets, and a single static binary
  (no runtime) for a distroless image.
- tonic accepts a custom incoming stream (`serve_with_incoming_shutdown`),
  so we own the TLS acceptor and can reload certificates
  ([[decisions/tls-reload]]).
- A Go server could reuse Talos's own stubs, but the brief chose Rust, and
  the protocol is two unary RPCs.

## Approved crates

tonic, tonic-prost, prost, tokio, rustls, tokio-rustls, reqwest, serde,
serde_json, toml, uuid, base64, arc-swap, tokio-stream, zeroize, thiserror,
anyhow, clap, tracing, tracing-subscriber, axum (already a tonic
dependency), prometheus; dev: rcgen, tempfile. Ask before adding others.
