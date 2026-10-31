---
title: Build pipeline
category: component
tags: [devbox, melange, apko, ci, cosign, release]
date: 2026-10-31
---

# Build pipeline

Mirrors container-dropshipping's pipeline, for one image built from this
repo's own source.

## Toolchain

`devbox.json` + `devbox.lock` (nixpkgs): rustc/cargo/clippy/rustfmt 1.99,
gcc, protobuf (protoc), openbao, grpcurl, melange, apko, cosign, go-task,
bubblewrap, python3, jq. CI installs them with `.github/actions/setup-tools`.
See [[decisions/melange-apko-devbox]].

## Scripts (`hack/`, shared by Taskfile and CI)

| Script | Does |
|---|---|
| `cargo-check.sh` | `cargo fmt --check`, clippy `-D warnings`, `cargo test` with `NYCKELPIGA_REQUIRE_BAO=1` (a missing `bao` fails instead of skipping) |
| `build.sh` | version check → export source (`git ls-files`, regular files only) → `cargo vendor --locked` → ephemeral melange key → melange build + test → `apko lock` + `lockfile.py merge` → `apko build --lockfile` → `notices.py` |
| `test.sh` | Docker: uid 65532, OCI labels, `--version`, no `/bin/sh`, then a real run with a throwaway cert: `/healthz` 200, `/readyz` 503 (no OpenBao), grpcurl `Seal` for an unknown node → `PermissionDenied`, and an audit line |
| `publish.sh` | `apko publish` with the build lock; resolves the **index** digest into `out/digest` |
| `lock.sh` | build the APK, `apko lock`, strip `@local` → `apko.lock.json` |
| `check-version.sh [tag]` | `melange.yaml` version = `Cargo.toml` version (= tag) |
| `lockfile.py` | copied from container-dropshipping: strip/merge/diff |
| `notices.py` | crates linked into the binary (cargo metadata, normal deps, musl target) with license + notice files → `out/notices.{json,md}` |

## melange (`melange.yaml`)

- Build environment: **Alpine v3.24** (rust 1.96, cargo-auditable, protoc,
  build-base), see [[decisions/static-musl-alpine-build]]. Test environment:
  Wolfi (binutils for `readelf`).
- Source = `--source-dir` with the exported tree plus `vendor/` and a
  `.cargo/config.toml` source replacement with `net.offline = true`. **The
  build is offline**, so a melange sandbox without network (local bwrap,
  air-gapped) works, and cargo verifies every crate against `Cargo.lock`.
- `RUSTFLAGS=-C target-feature=+crt-static`, `--target
  x86_64-alpine-linux-musl` (so proc macros and build scripts stay
  dynamic). Built with `cargo auditable`, so scanners can read the crate list
  from the binary.
- `melange test` asserts `--version` and **no ELF interpreter** (static). It
  runs in Wolfi, which shows the binary needs nothing from Alpine.
- `CARGO_TARGET_DIR=/var/cache/melange/target` (persisted via `--cache-dir
  .cache/melange`).

## apko (`apko.yaml`)

`talos-nyckelpiga@local` + `ca-certificates-bundle` (pulls
`wolfi-baselayout`). Entrypoint `/usr/bin/talos-nyckelpiga`, run-as 65532,
OCI annotations, `archs: [x86_64]`. About 3.4 MB.

### Lockfile

Same scheme as container-dropshipping
(`troubleshooting/apko-lockfile-local-packages.md` there): the committed lock
holds **Wolfi packages only**. The `@local` APK's control hash changes on
every commit, so `lockfile.py merge` adds it at build time and fails if
`apko.yaml` changed without a relock or the resolved Wolfi set drifted.

**No lock-refresh workflow (decided 2026-10-31).** The runtime lock is
`wolfi-baselayout` + `ca-certificates-bundle`: data only, no code that a
Wolfi CVE fix would change, and the binary is static. Images are published
only from release tags, so a refresh PR wouldn't ship anything by itself.
Run `task lock` before tagging a release instead. Revisit if the image gains
code packages or publishes on merge.

## CI

`.github/workflows/ci.yml` (PRs and manual dispatch, `contents: read`):

- `rust`: `hack/cargo-check.sh` (includes the OpenBao integration test).
- `image`: build, crate-license summary, `hack/test.sh`, publish dry run.
- `ci-ok`: the single required check.

`.github/workflows/release.yml` (tag `v*`): tag/version check, Rust checks,
build, test, then with `packages: write`, `id-token: write` and
`attestations: write`: `hack/publish.sh` (`PUBLISH_VERSION=1` → tags
`X.Y.Z` + `sha-<short>`), `cosign sign` on the index digest, `cosign attest`
of the SPDX SBOM and the notices (`https://github.com/backend-bunny/talos-nyckelpiga/notices/v1`),
and `actions/attest-build-provenance`.

Caches (`setup-tools`): `~/.cargo/registry`, `~/.cargo/git`, `target`, and
`.cache` (melange APK cache + release target), keyed on `Cargo.lock`,
`melange.yaml`, `apko.lock.json` and `devbox.lock`.

## Releasing

1. Bump `version` in `Cargo.toml` and `melange.yaml` (same value), `cargo
   update -w`, `task lock`, PR, merge.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. Take the digest from the run summary; consumers pin it.

## Gotchas

- Local `devbox install` needs the nix daemon socket. In a sandboxed agent
  session the user has to run it.
- The integration test's `bao server -dev` needs a writable `HOME` (it
  writes `~/.vault-token`); the test sets one.
- `hack/test.sh` needs Docker; sandboxed agent sessions usually can't reach
  the socket, but CI can.
