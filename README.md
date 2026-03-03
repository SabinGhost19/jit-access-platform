# JIT Access Platform

Zero-Trust Just-In-Time Access project for Kubernetes, structured into 3 main components:

- `helm/jit-access` – single chart for Operator + Backend + Frontend deployment
- `operator` – Python operator using `kopf` for JIT lifecycle and anti-abuse policies
- `backend` – FastAPI service for JWT auth, dashboard, sessions, audit, and kill switch
- `frontend` – enterprise-grade Vue.js SPA (Light theme by default + Dark Mode toggle)

## Quick deploy

```bash
helm upgrade --install jit-access ./helm/jit-access -n jit-system --create-namespace
```

## Admin UI toggle

- `adminUI.enabled: true` → deploy all components
- `adminUI.enabled: false` → deploy Operator only

## Docker images (production-ready)

- `operator/Dockerfile` – multi-stage Python build + non-root runtime
- `backend/Dockerfile` – multi-stage Python build + non-root runtime
- `frontend/nginx.conf` + `frontend/Dockerfile` – Vite build + static serving via Nginx

## CI/CD workflows

- `.github/workflows/jit-access-platform-ci.yaml`
  - `helm lint` and `helm template` validation
  - automatic semantic tag bump (`vX.Y.Z`) on `main`
  - GHCR build and push for each component:
    - `ghcr.io/<owner>/jit-operator`
    - `ghcr.io/<owner>/jit-backend`
    - `ghcr.io/<owner>/jit-frontend`
  - Helm chart packaging and push to OCI registry (GHCR)
- `.github/workflows/semantic-release.yml` – automated semantic release (versions + changelog)
- `.github/workflows/renovate.yml` – automated dependency update workflow
