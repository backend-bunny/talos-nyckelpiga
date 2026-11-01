# talos-nyckelpiga Helm chart

Runs [talos-nyckelpiga](https://github.com/backend-bunny/talos-nyckelpiga),
a Talos Linux KMS server backed by OpenBao transit, on Kubernetes.

```sh
helm install kms oci://ghcr.io/backend-bunny/charts/talos-nyckelpiga \
  --version 0.1.0 --namespace kms -f values.yaml
```

Each released chart version defaults to the image digest released with it.
Verify the chart signature before installing:

```sh
cosign verify ghcr.io/backend-bunny/charts/talos-nyckelpiga:0.1.0 \
  --certificate-identity-regexp '^https://github.com/backend-bunny/talos-nyckelpiga/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Before you install

- **A publicly trusted certificate** for the KMS hostname in a
  `kubernetes.io/tls` Secret (`tls.secretName`). Talos can't be given a
  custom CA for the KMS endpoint. A cert-manager `Certificate` works; renewals
  are picked up without a restart.
- **OpenBao**: a transit key per node (`talos-kms-<uuid>`), a policy with
  `update` on `transit/encrypt/talos-kms-*` and `transit/decrypt/talos-kms-*`,
  and a Kubernetes auth role bound to this release's service account
  (default name: the release fullname, e.g. `kms-talos-nyckelpiga`) in the
  release namespace. If the role sets an `audience`, set
  `openbao.auth.tokenAudience` to match.
- **With `grpc.hostPort.enabled` (default)**, the namespace must allow
  hostPort, which both baseline and restricted Pod Security forbid:
  `pod-security.kubernetes.io/enforce: privileged`. **With hostPort off**
  (LoadBalancer/NodePort Service or TLSRoute), the pod satisfies
  `restricted`: non-root 65532, read-only root, no capabilities,
  RuntimeDefault seccomp, only configMap/secret/projected volumes.

## Minimal values

```yaml
tls:
  secretName: kms-tls
openbao:
  address: https://openbao.openbao.svc:8200
  caCert:
    configMap: openbao-ca   # if OpenBao uses a private CA
  auth:
    role: talos-nyckelpiga
allowlist:
  nodes:
    # talosctl -n <node> get systeminformation -o jsonpath='{.spec.uuid}'
    - uuid: 4c4c4544-0042-3510-8051-b4c04f4e3732
      label: worker-1
```

## Exposure

| Mode | Values | Notes |
|---|---|---|
| **hostPort** (default) | `grpc.hostPort.enabled: true` | Pods on the control planes (default `nodeSelector`/`tolerations`), one per node (`podAntiAffinity: hard`). Talos dials a node IP directly, e.g. a name pinned with `machine.network.extraHostEntries`. Fewest moving parts at boot. |
| **LoadBalancer / NodePort Service** | `grpc.hostPort.enabled: false`, `service.type: LoadBalancer` (or `NodePort`), address via `service.annotations` (e.g. `lbipam.cilium.io/ips`, `metallb.io/loadBalancerIPs`) | An internal LB address on the nodes' network replaces hostPort: no gateway, TLS still ends in the pod, namespace can be `restricted`. Set `externalTrafficPolicy: Local` to keep the node address as the audit `peer`; with `Cluster` it's SNATed. Restrict with `loadBalancerSourceRanges`. |
| **Gateway API, TLS passthrough** | `tlsRoute.enabled: true`, `hostnames`, `parentRefs` | The Gateway routes by SNI and the server still terminates TLS with its own cert. Needs a listener with `protocol: TLS`, `tls.mode: Passthrough`. The audit log's `peer` is then the gateway's address. Unsealing at boot then depends on the gateway too. |

Both can be on at once. Keep the endpoint internal either way: the KMS
protocol has no client authentication. Terminating TLS at the gateway
(GRPCRoute) isn't supported: it would put key material on the pod network
in plaintext.

## Behaviour

- **Rollouts**: with hostPort or hard anti-affinity, pods are replaced one
  at a time (`maxSurge: 0`), since a replacement can't start next to the old
  pod. Otherwise a new pod starts first (`maxSurge: 1`, `maxUnavailable: 0`).
  Override with `rollingUpdate`. A new pod is Ready only once it's logged in
  to OpenBao, so a rollout pauses while OpenBao is down rather than
  replacing working pods.
- **Services**: `<fullname>` carries only gRPC (type from `service.type`),
  and `<fullname>-metrics` (ClusterIP) carries health/metrics, so metrics
  are never exposed on a load balancer.
- **Config changes** roll the pods (checksum annotation). **Allowlist and
  TLS Secret changes don't**: the server reloads them, after the kubelet has
  synced the volume (up to about a minute) plus `reloadIntervalSecs`.
- A **PodDisruptionBudget** (`maxUnavailable: 1`) keeps node drains from
  taking every KMS pod at once.
- The server's own projected service-account token is mounted
  (`automountServiceAccountToken: false` otherwise).

## Values

See [`values.yaml`](values.yaml) (every key is commented) and
[`values.schema.json`](values.schema.json). Main groups: `image`, `tls`,
`openbao` (address, CA, transit mount, key template, auth), `allowlist`
(`nodes` or `existingConfigMap` with key `allowlist.toml`), `grpc.hostPort`,
`service` (type, annotations, `externalTrafficPolicy`, `nodePort`,
load-balancer class and source ranges), `rollingUpdate`, `tlsRoute`, `serviceMonitor`, `networkPolicy`, `pdb`, scheduling
(`nodeSelector`, `tolerations`, `podAntiAffinity`, `affinity`,
`priorityClassName`).

## Development

`task chart` (from the repo root, in `devbox shell`) runs `helm lint
--strict`, renders every `ci/*-values.yaml`, validates the output with
kubeconform against pinned Kubernetes 1.37 and CRD schemas, compares it with
the golden files in `tests/`, passes the rendered config and allowlist
through the server's own parser (`--check-config`), and checks that invalid
values fail. `task chart:golden` accepts an intended rendering change.
