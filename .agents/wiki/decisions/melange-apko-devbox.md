---
title: melange + apko on Wolfi, toolchain via devbox
category: decision
tags: [melange, apko, devbox, wolfi]
date: 2026-10-31
---

# melange + apko, devbox

Same decisions and reasons as container-dropshipping:

- **No Dockerfile.** melange turns source into a signed APK and apko
  assembles a distroless image from APKs, with an SBOM. Reproducible
  timestamps come from `SOURCE_DATE_EPOCH` = commit time.
- **Ephemeral melange keys** (container-dropshipping
  `decisions/ephemeral-melange-keys-keyless-cosign.md`): the APK signature
  only bridges melange → apko within one job. Image trust comes from keyless
  cosign plus attestations.
- **devbox** (container-dropshipping `decisions/devbox-toolchain.md`): one
  nixpkgs lock for CI and local, Renovate's `devbox` manager for bumps.

What we do differently:

- Source is this repo (`--source-dir`), not an upstream `git-checkout`.
- The build environment is Alpine, not Wolfi ([[decisions/static-musl-alpine-build]]).
- Crates are vendored on the host and the build is offline.
- One image, so the scripts take no component argument.
- Publishing happens on release tags, not on every push to main.
- Notices come from `cargo metadata`, not source archives.
- No lock-refresh workflow ([[components/build-pipeline]]).
