---
title: One transit key per node; ciphertext returned verbatim; UUID as AAD
category: decision
tags: [openbao, transit, revocation, aad]
date: 2026-10-31
---

# One transit key per node

## Decision

- `node_uuid` → transit key `talos-kms-<uuid>` (`key_template`). Seal =
  `encrypt`, Unseal = `decrypt` on that key.
- The blob Talos stores is transit's ciphertext string (`vault:vN:…`) as
  bytes, unchanged.
- The canonical node UUID is passed as `associated_data` (default on).
- The server never creates keys. The policy grants `update` only on
  `transit/encrypt|decrypt/talos-kms-*`. Verified: with only `update`,
  encrypt on a missing key is a 403 and creates nothing (OpenBao v2.7.2
  `path_encrypt.go:156–164,282–296`, `request_handling.go:471–500`).

## Why

- **Revocation:** deleting one key makes that node's disks permanently
  unsealable without touching other nodes (needs `deletion_allowed=true`).
  Decrypt then returns 400 `encryption key not found` → `NOT_FOUND`.
- **Rotation:** the version prefix lets transit decrypt old blobs after
  `rotate`. `min_decryption_version` can later retire old versions once
  blobs have been re-sealed. Re-wrapping a stored blob would need Talos to
  rewrite its LUKS token, which it only does on key re-enrollment.
- **AAD:** ties a blob to its node UUID. With per-node keys a wrong-node
  unseal already fails, but AAD keeps that true if someone shares a key
  (custom `key_template`) or copies a blob. Costs nothing for AES-GCM.
  Changing `associated_data` later breaks every existing blob.
- **No auto-create:** a key for a node is an explicit provisioning step,
  outside this repo.
