---
title: Static musl binary built in an Alpine melange environment
category: decision
tags: [musl, static, alpine, wolfi, melange, lgpl]
date: 2026-10-31
---

# Static musl binary, built on Alpine

## Context

The maintainer chose a static musl binary (smaller image, no libc).
**Wolfi has no musl Rust target**: its `rust-1.99` is glibc-only and there
is no musl package in the index (checked 2026-10-31). Wolfi's `glibc-dev`
does ship `libc.a`, so a static **glibc** binary (`+crt-static`) would build.
But it would link LGPL-2.1 code into our binary, with relinking obligations
(§6) that container-dropshipping's dynamically linked images don't have.

## Decision

melange builds in an **Alpine** environment (`v3.24` main + community,
signed by `alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub`): Alpine's
`rust` targets musl natively, and `RUSTFLAGS=-C target-feature=+crt-static`
gives a static-pie binary. The **runtime image stays Wolfi** (apko only
installs the APK + `ca-certificates-bundle` from Wolfi). Suggested by the
maintainer on 2026-10-31.

## Consequences

- Release compiler = Alpine's rust (1.96.1 on v3.24). `rust-version = "1.96"`
  in `Cargo.toml`. CI lints/tests with devbox's newer rustc, so code must
  still build on 1.96. Renovate proposes Alpine branch bumps for approval
  only.
- The build environment isn't locked the way `apko.lock.json` locks the
  runtime. A stable Alpine branch only takes fixes, and melange's SBOM
  records what was installed.
- musl (MIT) has no copyleft obligations. Image licenses: Apache-2.0 AND
  MPL-2.0 (proto), plus the permissive crate licenses in the notices
  attestation.
- musl's allocator is slower than glibc's, which doesn't matter at a few
  requests per boot.
- DNS: musl's resolver reads `/etc/resolv.conf` directly, which works in pods.
