# Agent Guide — talos-nyckelpiga

> A Talos Linux KMS server backed by OpenBao transit: one revocable key per
> node for LUKS-encrypted Talos volumes.

This repo is a Rust gRPC server implementing the Talos `sidero.kms`
`Seal`/`Unseal` protocol on top of OpenBao transit `encrypt`/`decrypt`, plus
the pipeline that ships it as a minimal, signed OCI image at
`ghcr.io/backend-bunny/talos-nyckelpiga`. Operational knowledge lives in
`.agents/wiki/`: read it first.

## Hard rules

Security invariants of the server:

- **Never log key material.** No plaintext, ciphertext, request `data`,
  OpenBao tokens or service-account JWTs in logs, metrics labels or error
  messages. The integration test greps the full log output at TRACE level for
  them; keep that test passing and extend it when adding log fields.
- **Allowlist before OpenBao.** A node UUID is validated and looked up in the
  allowlist before any OpenBao request. An unknown node gets
  `PERMISSION_DENIED` and causes no OpenBao call.
- **OpenBao is the only key holder.** No keys in this repo, the image, the
  config or memory beyond one request. **No break-glass or static-key path**:
  it would defeat revocation. `token` auth is an OpenBao credential, not a
  key.
- **One transit key per node; return transit's ciphertext verbatim.** Never
  share keys between nodes or re-encode the `vault:vN:…` string. Rotation and
  revocation depend on it.
- **Zeroize what we own.** Plaintext buffers, tokens and the TLS key are
  wiped on drop (`zeroize`). Copies inside reqwest/hyper/tonic can't be
  reached. That is documented, not a reason to skip ours.
- **Fail closed on reload.** A broken certificate or allowlist update keeps
  the previous one and is reported. It never empties or disables either.

Build rules (as in container-dropshipping):

- **No Dockerfiles.** The image is built only with melange (source → APK)
  and apko (APKs → image).
- **Runtime image: Wolfi only. Build environment: Alpine (musl).** Wolfi has
  no musl Rust target, so `melange.yaml` builds the static binary in Alpine
  `v3.x`. See `.agents/wiki/decisions/static-musl-alpine-build.md`. Never put
  Alpine packages in `apko.yaml`.
- **Static binary, distroless image.** No shell, no package manager, no
  libc. `melange test` fails if the binary has an ELF interpreter.
- **Non-root, numeric UID.** `accounts.run-as: 65532`.
- **Hermetic build.** Crates are vendored on the host (`cargo vendor
  --locked`) and melange builds offline. `Cargo.lock` is committed.
- **Ephemeral melange keys.** Generated per build, never committed, stored
  or reused. Image trust comes from keyless cosign.
- **Committed apko lock, Wolfi packages only.** `apko.lock.json` is
  regenerated with `task lock` in the same PR as any `apko.yaml` change. See
  `.agents/wiki/components/build-pipeline.md`.
- **Pin everything.** Actions by full SHA with a version comment, toolchain
  in `devbox.json` + `devbox.lock`, crates in `Cargo.lock`.
- **Releases come from release-please.** Never bump versions or push
  release tags by hand: release-please's `chore: release X.Y.Z` PR sets
  `Cargo.toml`/`Cargo.lock`, `melange.yaml` and the chart (lines marked
  `x-release-please-version`) together, and merging it publishes.
  `hack/check-version.sh` fails if they disagree.
- **Conventional Commits.** PR titles and commit subjects are
  `type(scope)!: subject` (`hack/check-commits.sh`, run in CI): they decide
  the next version and the changelog.
- **Chart renders are reviewed.** Any template or values change updates the
  golden files (`task chart:golden`) in the same PR. The rendered config must
  pass the server's `--check-config` (`hack/chart-test.sh`). Never put TLS
  keys, tokens or OpenBao credentials into chart values: the chart only
  references existing Secrets.
- **x86_64 only** for now. Adding aarch64: `ARCHS` in `hack/lib.sh` and
  `archs` in `apko.yaml`.
- **Never push to `main` directly.** Branch, PR, `ci-ok` green.

## Layout

```
src/                # server: config, allowlist, bao (OpenBao client), service (gRPC), tls, health, metrics, watch
proto/kms.proto     # vendored sidero.kms protocol (MPL-2.0, byte-for-byte upstream below the header)
build.rs            # tonic-prost-build codegen (protoc from devbox / the build environment)
tests/integration.rs# against a real `bao server -dev`, gRPC over TLS
charts/talos-nyckelpiga/ # Helm chart (ci/ value sets, tests/ golden renders)
examples/           # config.toml, allowlist.toml, selfsigned.rs (test cert for hack/test.sh)
melange.yaml        # static binary APK (Alpine musl build env)
apko.yaml           # distroless Wolfi image
apko.lock.json      # Wolfi packages only, changed only via PR
hack/               # build/test/lock/publish/notices scripts shared by CI and Taskfile
.github/workflows/  # ci (PR), release-please (main → release PR → publish), release (called/dispatch)
release-please-config.json, .release-please-manifest.json # release automation
.github/actions/    # setup-tools: devbox toolchain, bwrap sysctl, caches
devbox.json/.lock   # pinned toolchain
Taskfile.yml        # local entry points (task check / image / image:test / lock)
renovate.json       # Renovate config
.agents/wiki/       # operational knowledge (index.md, log.md, components/, decisions/, troubleshooting/)
```

## Publishing contract

- Image: `ghcr.io/backend-bunny/talos-nyckelpiga`, public on GHCR.
- Published only when a release-please release PR is merged (tag `vX.Y.Z`
  and a GitHub Release). Tags: `X.Y.Z` and immutable `sha-<short>`.
  Consumers pin by **digest**.
- Helm chart: `oci://ghcr.io/backend-bunny/charts/talos-nyckelpiga`,
  version `X.Y.Z`, published by the same release with `image.digest` set to
  that release's image digest, and cosign-signed the same way.
- The image index digest is cosign-signed keylessly (GitHub OIDC) and carries the
  SPDX SBOM, build provenance and the crate license notices
  (`…/talos-nyckelpiga/notices/v1`) as attestations. Verify with
  `cosign verify ghcr.io/backend-bunny/talos-nyckelpiga@<digest> --certificate-identity-regexp '^https://github.com/backend-bunny/talos-nyckelpiga/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`.

## Dependency updates

Renovate (`renovate.json`) owns crate updates (grouped, plus weekly
`Cargo.lock` maintenance), action SHAs, the devbox toolchain, and the Alpine
branch in `melange.yaml` (Dependency Dashboard approval only: it changes the
release compiler). It doesn't touch `apko.lock.json`. Merge a `task lock`
PR before a release PR when Wolfi updates should ship; there is deliberately
no lock-refresh workflow
(`.agents/wiki/components/build-pipeline.md`). Adding a crate outside the
existing set needs the maintainer's OK.

## Wiki

Keep `.agents/wiki/` current: after any change, update or create the relevant
component/decision/troubleshooting page, refresh `index.md`, and add a dated
entry at the top of `log.md`. Check it before troubleshooting. Claims about
Talos or OpenBao behaviour cite the source file and version they came from.

## What NOT to do

- Do not add a static key, key file, "emergency" decrypt path or any other
  way to unseal without OpenBao.
- Do not log, trace or put into metrics anything derived from request data,
  plaintexts, ciphertexts or tokens.
- Do not call OpenBao before the allowlist check, or let a missing key be
  created implicitly (the policy must not grant `create`).
- Do not add Dockerfiles, a Docker build, or Alpine packages to the runtime
  image.
- Do not store, commit or reuse a melange signing key.
- Do not use `latest`/floating tags in workflows or consumer docs.
- Do not grant workflows more than `contents: read` by default. Elevate per
  job (`packages: write`, `id-token: write`, `attestations: write`) only where
  it publishes.
- Do not run `pull_request_target` or give PR builds publish/OIDC permissions.
- **This repo is public.** Do not name private clusters, hosts, domains or
  repositories that consume it, in code, docs, examples, commits or the wiki.
  Describe the runtime contract instead (`kms.example.com`, "a Talos cluster
  whose nodes reach the KMS over a private network").
- No `CLAUDE.md`: this file is the single agent guide.
