---
title: Helm chart
category: component
tags: [helm, kubernetes, hostport, gateway-api, tlsroute]
date: 2026-10-31
---

# Helm chart (`charts/talos-nyckelpiga`)

User docs: `charts/talos-nyckelpiga/README.md`. Design: [[decisions/kubernetes-exposure]].

## Resources

| Template | Renders |
|---|---|
| `deployment.yaml` | Deployment: default 3 replicas, rolling update computed (`maxSurge 0`/`maxUnavailable 1` with hostPort or hard anti-affinity, else `1`/`0`; `rollingUpdate` overrides, surge with hostPort is refused), control-plane `nodeSelector` + toleration, `podAntiAffinity: hard\|soft\|none`, hostPort 4050 (optional), probes `/healthz` (liveness) and `/readyz` (readiness = OpenBao token held), restricted-style security context |
| `configmap.yaml` | `<fullname>` with `config.toml` (rendered from values, strings via `toJson`); `<fullname>-allowlist` with `allowlist.toml` unless `allowlist.existingConfigMap` |
| `serviceaccount.yaml` | SA with `automountServiceAccountToken: false` |
| `service.yaml` | `<fullname>`: `grpc` 4050 only, `service.type` ClusterIP/LoadBalancer/NodePort (annotations, `externalTrafficPolicy`, `ipFamilyPolicy`/`ipFamilies`, `nodePort`, LB class/source ranges); `<fullname>-metrics`: ClusterIP `http` 8080, label `component: metrics` |
| `tlsroute.yaml` | optional Gateway API TLSRoute (`gateway.networking.k8s.io/v1`, standard channel since v1.7.0) |
| `pdb.yaml` | `maxUnavailable: 1` (default on) |
| `servicemonitor.yaml` | optional, selects the `component: metrics` Service, `/metrics` on `http` |
| `networkpolicy.yaml` | optional: ingress 4050 (from `grpcFrom`, default any), 8080 (from `healthFrom`); egress to OpenBao (`openbaoTo`, port 8200) and DNS in kube-system |

## Mounts and reloads

| Path in pod | Source | Change takes effect |
|---|---|---|
| `/etc/talos-nyckelpiga/config.toml` | config ConfigMap (`subPath`) | rollout (`checksum/config` annotation) |
| `/etc/talos-nyckelpiga/tls/` | existing TLS Secret (dir mount) | live: kubelet sync + `reloadIntervalSecs` |
| `/etc/talos-nyckelpiga/allowlist/` | allowlist ConfigMap (dir mount) | live, same |
| `/etc/talos-nyckelpiga/openbao-ca/` | optional ConfigMap or Secret | next pod start (CA is read at startup) |
| `/var/run/secrets/talos-nyckelpiga/serviceaccount/token` | projected SA token (`expirationSeconds` 3600, optional audience) | the kubelet rotates it; read at every login |

TLS and the allowlist must be **directory** mounts: `subPath` mounts never
receive updates.

## Tests (`hack/chart-test.sh`, `task chart`)

For each `ci/*-values.yaml` (minimal, full, gateway-only, loadbalancer): `helm lint
--strict`, `helm template` → kubeconform `-strict` with schemas pinned to
commits (yannh/kubernetes-json-schema `e0c72a1…` for Kubernetes 1.37.0,
datreeio/CRDs-catalog `3eb90d4…` for TLSRoute and ServiceMonitor), diff
against `tests/<name>.golden.yaml`, and the rendered `config.toml` +
`allowlist.toml` through `talos-nyckelpiga --check-config`. Value sets with
hostPort off must render no host ports, host namespaces, hostPath or
privileged containers (restricted-compatible). Then 14 invalid value sets
must fail (schema or `fail`/`required`).

Validation is split: the JSON schema covers types, UUID syntax, digest and
key-template shape; templates cover cross-field rules (`required`
address/role/secret, non-empty allowlist, TLSRoute hostnames/parentRefs, one
CA source).

## Publishing

On a release tag, `hack/chart-publish.sh` copies the chart, sets
`image.digest` to the image just published, packages it (`.helmignore`
drops `ci/` and `tests/`), pushes to `oci://ghcr.io/backend-bunny/charts`,
and the workflow cosign-signs the chart digest. Chart version = app
version = image version.
