# JIT Access Test Scenarios

This directory contains end-to-end Kubernetes manifests for validating core JIT behavior and anti-abuse controls.

## Execution Order

1. Apply prerequisites:

```bash
kubectl apply -f scenarios/00-prereqs.yaml
```

2. Run scenario manifests:

```bash
kubectl apply -f scenarios/10-happy-path.yaml
kubectl apply -f scenarios/20-concurrent-limit.yaml
kubectl apply -f scenarios/30-hard-cap.yaml
kubectl apply -f scenarios/40-blocked-user.yaml
```

3. Inspect CR status:

```bash
kubectl -n jit-system get jitaccessrequests
kubectl -n jit-system get jitaccessrequest jit-happy-path -o yaml
```

4. Cleanup test resources:

```bash
kubectl delete -f scenarios/90-cleanup.yaml --ignore-not-found=true
```

## Scenario Coverage

- `10-happy-path.yaml`
   - Valid request expected to move to `ACTIVE`.
- `20-concurrent-limit.yaml`
   - Second concurrent request for same identity expected to be denied with `DENIED_CONCURRENT_LIMIT`.
- `30-hard-cap.yaml`
   - Oversized duration request expected to be approved with policy-enforced capping.
- `40-blocked-user.yaml`
   - Blacklisted identity expected to be denied with `BLOCKED_BY_POLICY`.

## Operational Notes

- Scenarios target CR namespace `jit-system`.
- `requestedRole: view` requires that role to be available and bindable in target namespaces.
- Concurrent limit validation assumes the happy-path session is still active when scenario 20 is applied.
