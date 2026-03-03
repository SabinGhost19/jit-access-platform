# JIT Access Platform

Zero-Trust Just-In-Time access platform for Kubernetes, delivered as a single Helm-based deployment with three coordinated services:

- [Operator](operator) for JIT lifecycle orchestration and anti-abuse enforcement.
- [Backend API](backend) for authentication, metrics, session control, and audit exposure.
- [Admin SPA](frontend) for operational visibility and real-time revocation actions.

## Scope and Architecture

- Chart location: [helm/jit-access](helm/jit-access)
- Python operator package: [operator/src/jit_operator](operator/src/jit_operator)
- Python API package: [backend/src/jit_backend](backend/src/jit_backend)
- Frontend source: [frontend/src](frontend/src)
- Test scenarios: [scenarios](scenarios)

The platform uses a persistent SQLite database mounted through PVC for audit and session state continuity.

## Prerequisites

- Kubernetes cluster with RBAC enabled.
- Helm 3.x.
- Available StorageClass for dynamic PVC provisioning.
- Access to GHCR images for:
  - `ghcr.io/sabinghost19/jit-access-platform-operator`
  - `ghcr.io/sabinghost19/jit-access-platform-backend`
  - `ghcr.io/sabinghost19/jit-access-platform-frontend`

## Installation

### 1) Configure values

Use the example file as the baseline:

`helm/jit-access/values.example.yaml`

Minimum production-oriented adjustments:

- image tags for all three components
- `backend.jwt.secretKey`
- `adminAuth` strategy (`existingSecret` or chart-managed credentials)
- ingress host/TLS settings when ingress is enabled

### 2) Install or upgrade

```bash
helm upgrade --install jit-access ./helm/jit-access \
  -n jit-system \
  --create-namespace \
  -f ./helm/jit-access/values.example.yaml
```

### 3) Verify deployment

```bash
kubectl get pods,svc,ingress,pvc -n jit-system
helm status jit-access -n jit-system
```

## Accessing the Admin UI

When ingress is disabled, use port-forward:

```bash
kubectl -n jit-system port-forward svc/jit-access-frontend 8080:80
```

Open `http://localhost:8080`.

If credentials are chart-managed (`adminAuth.existingSecret: ""`), the default secret name is:

`jit-access-admin-auth`

Read credentials:

```bash
kubectl -n jit-system get secret jit-access-admin-auth -o jsonpath='{.data.username}' | base64 -d; echo
kubectl -n jit-system get secret jit-access-admin-auth -o jsonpath='{.data.password}' | base64 -d; echo
```

## Testing and Validation

Use the scenario pack in [scenarios](scenarios), documented in [scenarios/README.md](scenarios/README.md), to validate:

- happy path approval
- concurrency limit denial
- duration hard-cap enforcement
- blocked user policy denial

## CI/CD and Release Automation

- Main pipeline: [jit-access-platform-ci.yaml](.github/workflows/jit-access-platform-ci.yaml)
  - Helm lint/template validation
  - semantic tag bump
  - per-component image build and push
  - Helm chart package and OCI push
- Semantic release: [semantic-release.yml](.github/workflows/semantic-release.yml)
- Dependency automation: [renovate.yml](.github/workflows/renovate.yml)

## Containerization

- Operator image: [operator/Dockerfile](operator/Dockerfile)
- Backend image: [backend/Dockerfile](backend/Dockerfile)
- Frontend image: [frontend/Dockerfile](frontend/Dockerfile)
- Frontend Nginx runtime config: [frontend/nginx.conf](frontend/nginx.conf)

## Security Notes

- Prefer `adminAuth.existingSecret` in production.
- Rotate JWT secret periodically.
- Restrict ingress source ranges.
- Keep anti-abuse policy thresholds aligned with organizational access controls.

## Keywords

`zero-trust`, `just-in-time-access`, `kubernetes`, `helm`, `kopf`, `fastapi`, `vue`, `devsecops`, `rbac`, `audit-logging`, `cloud-native`, `platform-engineering`
