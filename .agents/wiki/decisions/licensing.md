---
title: Licensing
category: decision
tags: [license, apache, mpl, notices]
date: 2026-10-31
---

# Licensing

- **Repo: Apache-2.0** (`LICENSE`), as in container-dropshipping.
- **`proto/kms.proto`: MPL-2.0**, vendored from siderolabs/kms-client
  (MPL-2.0 repo). The upstream file has no header, so we added an MPL-2.0
  notice with the source commit above the unchanged body. MPL is file-level
  copyleft: changes to that file would have to stay MPL-2.0 and be public,
  which they are. Code generated from it is compiled into the binary, so the
  image declares `Apache-2.0 AND MPL-2.0`.
- **Crates in the binary** (158 as of 2026-10-31): MIT, Apache-2.0, ISC,
  BSD-3-Clause, Unicode-3.0, Unlicense; no copyleft. Their license and
  notice files go into the `notices/v1` cosign attestation
  (`hack/notices.py`). `tonic-prost` ships no license file (declared
  MIT only).
- **No libc in the binary from glibc**: static musl (MIT), see
  [[decisions/static-musl-alpine-build]]. The Wolfi runtime packages
  (baselayout, CA bundle) are listed in the SPDX SBOM attestation.
- This is an engineering reading, not legal advice.
