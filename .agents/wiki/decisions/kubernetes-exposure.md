---
title: Exposing the KMS on Kubernetes — hostPort default, TLS passthrough option
category: decision
tags: [kubernetes, hostport, gateway-api, ingress, tls]
date: 2026-10-31
---

# Exposure: hostPort by default, Gateway API passthrough as an option

## Context

Talos nodes dial `https://<name>:<port>` with grpc-go, verify against public
roots, and require ALPN `h2` ([[components/talos-kms-client]]). The KMS
protocol has no client authentication. Unseal happens during boot and is
retried every 30 s.

## Decision (maintainer, 2026-10-31)

- **Default: hostPort** on control-plane nodes, one pod per node (Deployment,
  hard anti-affinity). Talos reaches a node IP directly, e.g. a name pinned
  with `extraHostEntries`. Boot-time dependencies: the control-plane pods and
  OpenBao.
- **Option: LoadBalancer/NodePort Service** (added 2026-11-01, maintainer):
  an internal LB address (Cilium LB-IPAM, MetalLB) on the nodes' network.
  No gateway in the boot path, TLS ends in the pod, and the namespace can be
  `restricted`. `externalTrafficPolicy: Local` keeps the node address as the
  audit `peer` (with `Cluster` it's SNATed). Health/metrics moved to a
  separate ClusterIP Service so they're never on the load balancer.
- **Option: Gateway API `TLSRoute` with TLS passthrough.** The Gateway routes
  by SNI to the ClusterIP Service and the server terminates TLS with its own
  certificate. No server change is needed and TLS stays end to end.
- **Not supported: TLS termination at the gateway (GRPCRoute).** The server
  would need a plaintext h2c listener (or a second, private-CA TLS hop), and
  the 32-byte keys would cross the pod network in plaintext unless the CNI
  encrypts it. The audit `peer` would rely on `X-Forwarded-For`.

## Trade-offs of the gateway option

- More moving parts at boot: gateway controller, its pods, the
  LoadBalancer/VIP and DNS. That's fine for user volumes (the node joins
  before they unseal) but circular for STATE encryption using this KMS.
- The audit log's `peer` becomes the gateway pod address (no PROXY protocol
  support in the server).
- It must be an internal Gateway: with no client auth, a public listener
  exposes unsealing to anyone who has a node UUID and a LUKS header.
- Ingress controllers: only ones with TLS passthrough (e.g. ingress-nginx
  `ssl-passthrough`) work, and they aren't templated by the chart.

## Consequences

The namespace needs Pod Security `privileged` when hostPort is on (baseline
and restricted forbid hostPort). LoadBalancer/NodePort and gateway installs
can drop that (`grpc.hostPort.enabled: false`) and run anywhere
(`nodeSelector: {}`). With soft or no anti-affinity they also roll with a
surge pod, so a rollout never drops a ready replica.
