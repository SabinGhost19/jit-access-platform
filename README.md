<div align="center">

# JIT Access Platform

### Kubernetes-native Just-in-Time RBAC with manual approval, real-time UX, and full audit

<p>
  <img alt="License" src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square">
  <img alt="Kubernetes" src="https://img.shields.io/badge/kubernetes-1.27%2B-326CE5?style=flat-square&logo=kubernetes&logoColor=white">
  <img alt="Operator" src="https://img.shields.io/badge/operator-Kopf-3776AB?style=flat-square&logo=python&logoColor=white">
  <img alt="Helm" src="https://img.shields.io/badge/helm-3.x-0F1689?style=flat-square&logo=helm&logoColor=white">
  <img alt="API" src="https://img.shields.io/badge/api-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white">
  <img alt="UI" src="https://img.shields.io/badge/ui-Vue%203%20%2B%20Vuetify-4FC08D?style=flat-square&logo=vue.js&logoColor=white">
  <img alt="Identity" src="https://img.shields.io/badge/identity-Keycloak%20OIDC-4D4D4D?style=flat-square&logo=keycloak&logoColor=white">
</p>

<p>
  <img alt="CNCF" src="https://img.shields.io/badge/CNCF-cloud%20native-FFFFFF?style=flat-square&logo=cncf&logoColor=blue&labelColor=003566">
  <img alt="Zero Trust" src="https://img.shields.io/badge/architecture-Zero%20Trust-1B1F23?style=flat-square">
  <img alt="SLSA L3" src="https://img.shields.io/badge/SLSA-Level%203-success?style=flat-square">
  <img alt="Conventional Commits" src="https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?style=flat-square&logo=conventionalcommits&logoColor=white">
  <img alt="Semantic Release" src="https://img.shields.io/badge/semantic--release-enabled-e10079?style=flat-square&logo=semantic-release&logoColor=white">
  <img alt="Status" src="https://img.shields.io/badge/status-production%20ready-success?style=flat-square">
</p>

<sub>Self-hosted. Open standards. Zero vendor lock-in.</sub>

</div>

---

## Overview

**JIT Access Platform** grants short-lived, auditable Kubernetes RBAC
privileges to human operators on demand. It replaces standing administrative
credentials with a manual-approval workflow whose every decision is a
declarative Custom Resource in the cluster's own etcd.

A developer requests temporary `edit` on a namespace. A platform engineer
approves with a single click. The operator mints a short-lived service-account
token, scoped to the requested role and bounded by policy. When the timer
expires, the operator removes every privilege it created. Every step is
inspectable through `kubectl get jitar`.

The design is intentionally minimal: no proxies, no agents on worker nodes,
no SaaS dependency. Three primitives are sufficient — a Custom Resource, a
reconciler, and the native Kubernetes `TokenRequest` API.

---

## Standards alignment

- **NIST SP 800-207** — Zero Trust Architecture (per-request authorisation,
  short-lived tokens, no network-location trust).
- **CNCF principles** — declarative APIs, GitOps-compatible state, vendor-
  neutral identity (OIDC).
- **SLSA Level 3** — provenance attached to every operator image.
- **CIS Kubernetes Benchmark §5.1** — minimised RBAC surface.

---

## Documentation

Detailed technical documentation, including architecture, the CRD reference,
the security model, comparative analysis against alternative systems, and
deployment procedures, is available in [`docs/`](docs/).

---

## License

Released under the **Apache License 2.0**. See [`LICENSE`](LICENSE).

---

<div align="center">
  <sub>
    Built for the bachelor's thesis
    <i>Self-hosted Zero-Trust DevSecOps Reference Architecture for Kubernetes</i>.
  </sub>
</div>
