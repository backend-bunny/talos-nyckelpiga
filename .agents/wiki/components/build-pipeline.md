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
| `check-version.sh [tag]` | `melange.yaml` version = chart `version` = `appVersion` = `Cargo.toml` version (= tag) |
| `chart-test.sh` | Helm chart checks, see [[components/helm-chart]] |
| `chart-publish.sh` | package the chart with `image.digest` = `out/digest`, `helm push` to `oci://ghcr.io/backend-bunny/charts`, write `out/chart-digest` |
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
Merge a `task lock` PR before the release PR instead. Revisit if the image gains
code packages or publishes on merge.

## CI

`.github/workflows/ci.yml` (PRs and manual dispatch, `contents: read`):

- `conventional-commits` (PRs): `hack/check-commits.sh` on the PR title and
  every commit subject.
- `rust`: `hack/cargo-check.sh` (includes the OpenBao integration test).
- `chart`: `hack/chart-test.sh` and a package dry run.
- `image`: build, crate-license summary, `hack/test.sh`, publish dry run.
- `ci-ok`: the single required check.

`.github/workflows/release-please.yml` (push to main): see Releasing below.

`.github/workflows/release.yml` (`workflow_call` from release-please, or
`workflow_dispatch` with an existing tag to retry): checks out the tag,
tag/version check, Rust and chart checks,
build, test, then with `packages: write`, `id-token: write` and
`attestations: write`: `hack/publish.sh` (`PUBLISH_VERSION=1` → tags
`X.Y.Z` + `sha-<short>`), `cosign sign` on the index digest, `cosign attest`
of the SPDX SBOM and the notices (`https://github.com/backend-bunny/talos-nyckelpiga/notices/v1`),
and `actions/attest-build-provenance`. Then the chart: `helm registry
login` with `GITHUB_TOKEN`, `hack/chart-publish.sh`, `cosign sign` on the
chart digest. Finally the image/chart digests and `cosign verify` commands
are appended to the GitHub Release notes (`contents: write`).

Caches (`setup-tools`): `~/.cargo/registry`, `~/.cargo/git`, `target`, and
`.cache` (melange APK cache + release target), keyed on `Cargo.lock`,
`melange.yaml`, `apko.lock.json` and `devbox.lock`.

## Releasing

Automated with release-please, see [[decisions/release-please]].

1. Each push to `main` runs `release-please.yml`. It opens or updates the
   `chore: release X.Y.Z` PR (label `autorelease: pending`): version from the
   Conventional Commits since the last tag, `CHANGELOG.md`, and the bump in
   `Cargo.toml` + `Cargo.lock` (rust strategy) and in `melange.yaml` + the
   chart's `version`/`appVersion` (generic updater on the
   `# x-release-please-version` lines). It then dispatches `ci` on that
   branch, because a `GITHUB_TOKEN` push doesn't trigger `pull_request`, so
   `ci-ok` gates the merge.
2. Merging the PR makes the next `release-please.yml` run tag `vX.Y.Z` and
   create the GitHub Release, then call `release.yml` in the same run. A
   `GITHUB_TOKEN` tag push wouldn't trigger a tag workflow.
3. Optional before step 2: a `task lock` PR for newer Wolfi packages.

The chart golden files store `VERSION` in place of the chart version
(`hack/chart-test.sh` normalises it), so the release PR's bump needs no
regenerated goldens.

Retry a failed publish: run `release` by hand (`workflow_dispatch`) with
the existing tag. That re-pushes the `X.Y.Z` tags with a new digest, so only
do it if nothing was published, or bump with a `fix:` instead.

## Gotchas

- Local `devbox install` needs the nix daemon socket. In a sandboxed agent
  session the user has to run it.
- The integration test's `bao server -dev` needs a writable `HOME` (it
  writes `~/.vault-token`); the test sets one.
- `hack/test.sh` needs Docker; sandboxed agent sessions usually can't reach
  the socket, but CI can.
- In the sandboxed agent session `.github/` is read-only: stage workflow
  changes elsewhere and have the maintainer move them.
- One-time repo settings: "Allow GitHub Actions to create and approve pull
  requests" (release-please PR), and OIDC (`id-token: write`) allowed for
  workflows.
- First chart publish: the GHCR package `charts/talos-nyckelpiga` is
  created by the release job and may need its visibility set to public by
  hand (as with the image package).
