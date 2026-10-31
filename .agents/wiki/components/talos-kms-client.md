---
title: How Talos uses the KMS (verified from source)
category: component
tags: [talos, luks2, kms, grpc, smbios]
date: 2026-10-31
---

# How Talos uses the KMS

Read from source, not docs. Versions:

| Repo | Ref | Commit |
|---|---|---|
| siderolabs/talos | `v1.14.5` (= tip of `release-1.14`) | `dad8d3edfe7ca381044d7cad259fdf3030efa700` |
| siderolabs/kms-client | `v0.2.0` (Talos go.mod) | `296bf9a1085bd1a8dd06ba81b6969dddf196133c` |
| siderolabs/go-blockdevice | `v2.0.32` (Talos go.mod) | `dd15b28f01b8cb115be21751fe5307959afe131c` |
| siderolabs/go-smbios | `v0.3.4` | `063f5dc16e0a86d4dbb8290d197bdb134d9bafac` |
| grpc/grpc-go | `v1.83.2` (Talos go.mod) | `030ee8becb20ce4315d6bf2dfa26bdd876169dc4` |

Talos paths are relative to the talos repo root.

## What `Seal` receives

- `data` = **32 random bytes** (`crypto/rand`), raw.
  `node_uuid` = `SystemInformation.TypedSpec().UUID`. Nothing else: no PCRs,
  volume ID or salt. (`internal/pkg/encryption/keys/kms.go`,
  `KMSKeyHandler.NewKey`, lines 53–92.)
- The LUKS passphrase is `base64(key)`. On unlock `GetKey` (lines 95–127)
  base64-encodes `Unseal`'s response again, so **`Unseal` must return exactly
  the 32 raw bytes**.
- **`lockToState: true` doesn't change what the KMS sees.** `SaltedHandler`
  (`keys/salted.go:33–64`, wrapped in `keys/keys.go:75–81`) appends the STATE
  `DiskSalt` to the passphrase locally.
- The sealed blob goes into a LUKS2 token (ID = slot), type `sideroKMS`,
  `{"UserData":{"sealedData":"<base64>"},...}`
  (`keys/token.go:9`, `kms.go:30–33,84–89`; go-blockdevice
  `encryption/luks/token.go:10–22`, imported with `cryptsetup token import`
  in `luks.go:329–340`).
- Size: no Talos limit. The default LUKS2 metadata gives about 12 KiB of
  JSON, shared with the slots. A transit ciphertext for 32 bytes is about
  90 bytes. We cap `data` at 4 KiB.

## How Talos dials

`KMSKeyHandler.getConn` (`kms.go:129–151`), `internal/pkg/endpoint/endpoint.go`
`Parse` (lines 23–44):

- `https://host:port` → TLS. **Any scheme other than `grpc://` is TLS**,
  including `http://`. No scheme, or `grpc://`, means plaintext. A host
  without a port gets 443.
- TLS roots: `httpdefaults.RootCAs()` reads `/etc/ssl/certs/ca-certificates.crt`
  (`pkg/httpdefaults/tls.go`): the embedded bundle plus any
  `TrustedRootsConfig`. No per-KMS CA, client cert or ServerName option.
  For STATE the machine config (custom CAs) isn't loaded yet
  (`encryption.go:154–156`). **Use a publicly trusted cert.**
- grpc-go always offers ALPN `h2` and enforces it
  (`credentials/tls.go:239`, `GRPC_ENFORCE_ALPN_ENABLED` default true):
  **the server must select `h2`**.
- One new connection per call. Proxy env vars are honoured. Timeouts: 10 s
  per Seal/Unseal (`kms.go:54,101`), 20 s per key handler
  (`encryption.go:29,341`), 1 min for the encryption step
  (`volumes/encrypt.go:49,55`). No gRPC retry policy or `WaitForReady`.

## When `Unseal` fails at boot

- Errors are wrapped as **Retryable** "error opening encrypted volume"
  (`volumes/encrypt.go:101–104`; `tryHandlers` in `encryption.go:114–157,
  330–363` tries every slot first).
- `VolumeManagerController` (`controllers/block/volume_manager.go:119–136,
  344–371`) sets `Phase=Failed` and re-reconciles on a **fixed 30 s ticker**
  (plus any input change), without backoff or an attempt limit. `Failed`
  returns to the pre-fail phase (lines 578–580).
- **So a sealed or unreachable OpenBao heals within about 30 s of coming
  back, with no reboot.** Applies to user volumes. STATE: config
  acquisition waits on a definitive status (`controllers/config/acquire.go:252–271`).
  EPHEMERAL: `MountEphemeralPartition` waits with no timeout of its own. A
  sequencer-level timeout above that wasn't traced.
- **Talos never inspects gRPC status codes** (no `status.Code` anywhere in
  `internal/pkg/encryption`). A revoked node retries forever, the same as a
  transient outage.
- Status: `talosctl get volumestatus <id>` (phase, error).

## Which node UUID

- SMBIOS system UUID from `hardware.SystemInfoController`
  (`controllers/hardware/system.go:138–162`) via go-smbios `GetUUID`
  (`smbios/system_information.go:111–134`, middle-endian for SMBIOS ≥ 2.6),
  formatted by `google/uuid`: **lowercase, hyphenated**. Not
  `/sys/class/dmi/id/product_uuid`.
- META key `UUIDOverride` (0x0f) replaces it verbatim, without normalisation
  (`adapters/hardware/system_information.go:27–37`). An override that isn't a
  UUID is refused by our syntax check.
- Read it with `talosctl get systeminformation -o yaml` → `spec.uuid` (also
  the default table's `UUID` column).

## The reference server (kms-client `pkg/server`, not used here)

AES-256-GCM with one key file, no AAD, 1 s sleep per call. On a GCM failure
it **returns 32 random bytes with OK**. That's why we return errors instead.
