---
title: A Talos volume won't unseal
category: troubleshooting
tags: [talos, unseal, openbao, audit]
date: 2026-10-31
---

# A Talos volume won't unseal

Talos retries a failed unseal every 30 s indefinitely and ignores the gRPC
code ([[components/talos-kms-client]]). Find the cause in this server's audit
log. Each call logs `op`, `node_uuid`, `node_label`, `peer`, `result` and
`reason`.

| `result` / `reason` | Cause | Fix |
|---|---|---|
| `invalid_argument` "node_uuid is not a valid UUID" | `UUIDOverride` META value that isn't a UUID, or a client that isn't Talos | Check `talosctl get systeminformation` |
| `permission_denied` "node is not in the allowlist" (no `node_label`) | UUID missing from the allowlist, or changed (board swap, SMBIOS update) | Add it. Reload takes ≤ `reload_interval_secs` |
| `permission_denied` "openbao denied the request" | Policy doesn't cover the key name, or the key is **missing** (encrypt on a missing key is a 403 without `create`) | Create the key or fix the policy |
| `not_found` "transit key not found" | Key deleted: the node is revoked | Intended? Otherwise the disk is unrecoverable; reset the volume |
| `invalid_argument` "cipher: message authentication failed" | Blob sealed for another node UUID or another key, `associated_data` toggled, or tampered | Compare UUIDs, check `associated_data` |
| `unavailable` "Vault is sealed" / connect errors | OpenBao sealed or unreachable | Unseal OpenBao. Talos recovers within about 30 s |
| `unavailable` "not authenticated" | Login failing: check `nyckelpiga_openbao_auth_total{result="error"}` and WARN logs | Role, SA binding, CA, address |
| no audit line at all | Talos can't connect: DNS/`extraHostEntries`, firewall, cert not publicly trusted, ALPN | `grpcurl` from a node's network; check the cert chain |

On the node: `talosctl get volumestatus <id> -o yaml` shows the phase and
error.
