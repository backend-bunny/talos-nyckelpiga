---
title: Releases with release-please
category: decision
tags: [release, release-please, conventional-commits, github-actions]
date: 2026-10-31
---

# Releases with release-please

## Context

A release has to bump four version fields together (`Cargo.toml`,
`melange.yaml`, chart `version` and `appVersion`), then tag, publish and
sign the image and the chart. Done by hand that's error-prone, and there was
no changelog or GitHub Release.

## Decision (maintainer, 2026-10-31)

[release-please](https://github.com/googleapis/release-please) in manifest
mode (`release-please-config.json`, `.release-please-manifest.json`),
`googleapis/release-please-action` v5.0.0 pinned by SHA, with `GITHUB_TOKEN`
only.

- **Human gate:** releases happen when the `chore: release X.Y.Z` PR is
  merged, not on every merge. Fully automatic releases were rejected:
  nodes pull this image at boot.
- **Versioning:** `rust` strategy (Cargo.toml + Cargo.lock), plus `generic`
  extra-files for `melange.yaml` and `Chart.yaml` via
  `# x-release-please-version` line markers. The `yaml` updater was avoided
  because it re-serialises the file and drops comments.
  `bump-minor-pre-major`: before 1.0 a breaking change bumps the minor.
- **Publish in the same run:** the tag and Release are created with
  `GITHUB_TOKEN`, whose events don't trigger other workflows, so
  `release-please.yml` calls `release.yml` (`workflow_call`) when
  `release_created`. The tag-push trigger was removed, so hand-pushed tags
  don't publish.
- **CI on the release PR:** dispatched by the same workflow (`gh workflow
  run ci.yml --ref <branch>`), as container-dropshipping does for its
  lock-refresh PR.
- **Conventional Commits are enforced** in CI (`hack/check-commits.sh`: PR
  title + commit subjects), since they drive the version and the changelog.

## Consequences

- Chart golden files can't contain the version (`VERSION` placeholder),
  because release-please doesn't run our tooling on its PR.
- `apko.lock.json` isn't refreshed by the release PR; ship Wolfi updates
  with a `task lock` PR before it.
- Renovate's commit types are set explicitly (`renovate.json`): crate and
  devbox toolchain bumps are `fix(deps)`, so they produce a patch release;
  action bumps are `ci(deps)` (no release); Alpine branch bumps are
  `build(deps)`.
- Changelog sections: Features, Bug Fixes, Performance, Reverts, Build and
  Image, Dependencies; docs/ci/chore/test/refactor/style are hidden.
- Retrying a failed publish: `workflow_dispatch` of `release` with the tag.
