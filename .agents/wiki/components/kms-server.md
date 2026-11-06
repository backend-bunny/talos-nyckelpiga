---
title: KMS server
category: component
tags: [grpc, openbao, transit, tls, allowlist, audit]
date: 2026-11-06
---

# KMS server

The `talos-nyckelpiga` binary (`src/`). How Talos uses the KMS is in
[[components/talos-kms-client]].

## Protocol

`proto/kms.proto`, vendored from siderolabs/kms-client at
`83e0a2ec6b06668940ec31d64491d9b8a630524b` (the file is unchanged in
kms-client v0.2.0, which Talos v1.14.5 pins). Upstream has no license header;
the repo is MPL-2.0, so we added an MPL-2.0 header above the unchanged body.

```proto
service KMSService {             // package sidero.kms
  rpc Seal(Request) returns (Response);    // /sidero.kms.KMSService/Seal
  rpc Unseal(Request) returns (Response);
}
message Request  { string node_uuid = 1; bytes data = 2; }
message Response { bytes data = 1; }
```

No client authentication exists in the protocol. Defences here: allowlist,
per-node keys, associated data, audit log, revocation by deleting the key.

## Request flow (`src/service.rs`)

1. Peer address from the TLS connection (`tls::PeerAddr`).
2. **Allowlist** (`src/allowlist.rs`): `node_uuid` must be a 36-character
   hyphenated UUID (case-insensitive, canonicalised to lowercase), else
   `INVALID_ARGUMENT`. If it isn't listed: `PERMISSION_DENIED`. **No OpenBao
   request happens before this.**
3. `data` must be 1..4096 bytes (`bao::MAX_DATA_LEN`).
4. Key name = `key_template` with `{uuid}` (default `talos-kms-<uuid>`).
5. Seal: `POST /v1/<mount>/encrypt/<key>` with `plaintext` (base64) and
   `associated_data` = base64(uuid). Returns `data.ciphertext` bytes as-is.
   Unseal: `data` must be ASCII starting with `vault:v`, then
   `POST /v1/<mount>/decrypt/<key>`. Returns the decoded plaintext.
6. One audit event (target `audit`): `op`, `node_uuid` (only once it parsed,
   so arbitrary client strings aren't logged), `node_label`, `peer`, `result`
   (`ok` or the code name), `latency_ms`, plus `reason` on failure.
   Successes log at INFO, failures at WARN.

`associated_data` works for AEAD transit key types (aes128/256-gcm96,
chacha20/xchacha20-poly1305) without `derived`/`context` (OpenBao v2.7.2
`internal/builtin/logical/transit/path_encrypt.go:135–144`,
`sdk/helper/keysutil/policy.go:205–213`). Turning it off
(`associated_data = false`) breaks every existing blob: decryption needs the
same AAD.

## OpenBao client (`src/bao.rs`)

Plain reqwest + rustls (ring), see [[decisions/openbao-client-reqwest]].

- TLS roots: `openbao.ca_cert` only, else `$SSL_CERT_FILE`, else
  `/etc/ssl/certs/ca-certificates.crt` (Wolfi's `ca-certificates-bundle`).
  The selected file is polled with `server.reload_interval_secs` (including
  the environment/system bundle fallback). Multiple PEM certificate blocks
  support overlapping roots. Every certificate must parse; missing, empty,
  malformed or partly invalid updates retain the previous trust store, log
  an error and retry on every tick. Invalid startup bundles are fatal.
- Successful CA reloads atomically swap the reqwest client **and its pool**.
  New requests cannot reuse connections or TLS sessions authenticated by a
  removed root; in-flight requests may finish with their old snapshot. Tokens
  and their renewal state are preserved. Plain HTTP does not read/watch CAs.
- Plain HTTP remains supported, with a prominent startup security warning.
  The warning never includes the configured URL, which could contain secrets.
- All HTTP redirects are refused (authentication, renewal and transit).
  Redirect responses map to `UNAVAILABLE` with a fixed message; neither their
  Location nor their body is logged. Configure an endpoint that serves requests
  directly, rather than relying on redirects to another OpenBao node.
- **Kubernetes auth:** `POST auth/<mount>/login {role, jwt}` with the
  projected SA token (re-read on every login, so rotation is picked up).
- **Token auth:** a token file, validated with `auth/token/lookup-self`.
- `Bao::maintain` (background): log in (backoff 1 s → 30 s), renew with
  `auth/token/renew-self` at ⅔ of the TTL, log in again when renewal fails
  or the token isn't renewable.
- A transit call that gets **403** drops the token, logs in once (serialised,
  so concurrent 403s don't stampede) and retries once. A second 403 is
  `PERMISSION_DENIED`.
- `/readyz` is 200 while a non-expired token is held.

## Errors → gRPC codes

From `BaoError::from_response` (status + OpenBao's `errors` strings):

| OpenBao | Meaning | gRPC |
|---|---|---|
| connect error, timeout, 500/502/503/504, 429 | unreachable, sealed (`503 Vault is sealed`), standby, rate limit | `UNAVAILABLE` |
| no token / login failing | not authenticated yet | `UNAVAILABLE` |
| 3xx | redirect refused | `UNAVAILABLE` |
| 403 after a fresh login | policy denies the key, or encrypt on a missing key (needs `create`) | `PERMISSION_DENIED` |
| 400 `encryption key not found` | key deleted: node revoked | `NOT_FOUND` |
| 400 other (`cipher: message authentication failed`, soft-deleted key, bad ciphertext) | wrong node, tampered blob, AAD mismatch | `INVALID_ARGUMENT` |
| anything else | unexpected | `INTERNAL` |

Talos ignores the code and retries every failure every 30 s
([[components/talos-kms-client]]), so the codes are for operators, logs and
metrics. A sealed OpenBao self-heals: covered by the integration test.

## Listeners (`src/net.rs`)

Default `[::]:4050` (gRPC) and `[::]:8080` (health). The unspecified IPv6
address is bound with socket2 and `IPV6_V6ONLY` cleared explicitly, so it's
dual-stack regardless of `net.ipv6.bindv6only`. If IPv6 is missing
(EAFNOSUPPORT with `ipv6.disable=1`, or EADDRNOTAVAIL), it falls back to
`0.0.0.0` with a warning. Other addresses bind as given. IPv4 peers on the
dual-stack socket (`::ffff:a.b.c.d`) are canonicalised to plain IPv4 before
the audit log. Before 0.2.1 the defaults were `0.0.0.0`, which was IPv4 only.

## TLS (`src/tls.rs`)

Custom accept loop: TCP → rustls handshake (10 s timeout, concurrent) →
tonic `serve_with_incoming_shutdown`. ALPN offers only `h2` (grpc-go enforces
ALPN). The certificate comes from a reloading `ResolvesServerCert`, see
[[decisions/tls-reload]].

### Resource limits

- 64 accepted gRPC connections total, including queued connections and at most
  16 concurrent handshakes. Admission permits live until the sockets are dropped.
  Excess connections are closed before spawning tasks. Dropping the incoming
  stream closes the listener and aborts pending handshakes.
- After TLS, the 24-byte HTTP/2 client preface must arrive within 10 s; partial
  input cannot extend that deadline. Established connections have a 30 s idle
  timeout (reset only by peer input) and a 5 min absolute lifetime. The deadlines
  also apply when writes stall.
- Four concurrent streams/RPCs per connection, a 10 s RPC timeout, an 8 KiB
  header limit and a 4160-byte protobuf decoding limit (4096-byte data plus
  UUID/tags/lengths). The decoding limit rejects oversized messages before the
  application is invoked; ordinary requests still check the allowlist first.
- A separate global semaphore admits 32 active KMS transit operations.
  Overload returns `RESOURCE_EXHAUSTED` immediately, with no queue of plaintext
  buffers. The allowlist is checked before this gate too. Cancellation releases
  capacity and wipes the request's owned plaintext buffers.
- Health/metrics use a separate budget of 16 connections, with a 10 s idle
  timeout and a 60 s absolute lifetime, so that listener cannot bypass the
  gRPC resource limits.

These are fixed server limits; network access restrictions remain necessary.

## Reloads (`src/watch.rs`)

The certificate pair, allowlist and selected OpenBao CA bundle are polled every
`reload_interval_secs` (30 s) by hashing the contents, which works with
Kubernetes' `..data` symlink swaps. A change that fails to parse, or a cert
that doesn't match its key, keeps the previous version, logs an error,
increments `*_reloads_total{result="error"}` and is retried on every tick
until fixed. A bad allowlist or certificate **at startup** is fatal.

The CA watcher reopens `ca.crt` through `..data` on each tick, rather than
watching the old inode. The chart already uses a directory mount with `items`;
`subPath` would prevent updates reaching the process. Rotation takes the secret
controller refresh interval (if used), kubelet propagation (up to about a
minute), then one server poll. Publish old+new roots, wait for every replica's
successful reload, switch OpenBao's serving chain, verify, then retire the old
root. CA reload counters report parsing/client construction, not a connectivity
probe: a valid bundle containing the wrong roots will still be activated.

`--check-config` loads the config (with env overrides) and the allowlist
and exits: used by the chart tests ([[components/helm-chart]]) on every
rendered config.

## Zeroization

Wiped on drop: decrypt plaintext (`Zeroizing<Vec<u8>>`), request `data`
in the handler, the base64 encryption plaintext, response bodies, tokens,
JWTs and the TLS key file contents. Login and transit serialization borrow
secrets from these owners instead of copying them into ordinary JSON strings.
Cleanup works on success, error and cancellation; no wipe depends on reaching
code after an `.await`. **Not reachable:** the serialized request
body handed to reqwest, hyper/h2 buffers, and the response `Vec` tonic
encodes. The plaintext crosses those once per call.

## Metrics (`/metrics`)

`nyckelpiga_requests_total{op,result}`,
`nyckelpiga_request_duration_seconds{op}`,
`nyckelpiga_openbao_authenticated`, `nyckelpiga_openbao_auth_total{kind,result}`,
`nyckelpiga_tls_reloads_total{result}`,
`nyckelpiga_openbao_ca_reloads_total{result}`,
`nyckelpiga_allowlist_reloads_total{result}`, `nyckelpiga_allowlist_nodes`.
No node UUIDs in labels.

## Tests

- Unit: config parsing and env overrides, allowlist (syntax, duplicates,
  reload keeps the old list on error), error mapping, file watch, cert reload
  (mismatched pair rejected), redirect refusal for all five HTTP call paths,
  HTTP warning without URL disclosure, admission limits and recovery, fixed
  preface/idle/lifetime deadlines, handshake shutdown, and cancellation
  releasing transit capacity while preserving allowlist ordering.
- HTTPS CA tests: Kubernetes-style `..data` replacement with a live watcher,
  old+new root overlap, removal of an old root despite live old connection pools,
  preservation of tokens and redirect refusal, invalid/partial/empty/missing
  bundle recovery, retry without another file update, no CA reads for HTTP,
  and reload logs excluding file contents.
- `tests/integration.rs` (real `bao server -dev` and a tonic client over TLS,
  self-signed in the test only): round trip; unknown or malformed UUID; wrong
  node; tampered blob; no key auto-create with an `update`-only policy;
  rotation (v1 still unseals); sealed → `UNAVAILABLE` → unsealed heals;
  delete key → `NOT_FOUND`; allowlist hot reload; metrics; logs at TRACE
  contain no key/ciphertext/token; oversized protobuf rejection; certificate
  reload while a connection stays up;
  Kubernetes auth login against a fake TokenReview API.
- bao `-dev` writes `~/.vault-token`; the test gives it its own `HOME`.
