# JIT Access Platform (Operator Focus)

The backend, frontend, and scenario resources are deprecated in this module.

The repository now keeps:

- Operator implementation: [operator/src/jit_operator](operator/src/jit_operator)
- Operator Helm chart: [helm/jit-access](helm/jit-access)

## Scope

The operator handles JIT access lifecycle orchestration and policy enforcement.

## Helm Deployment

Use the chart to deploy the operator:

```bash
helm upgrade --install jit-access ./helm/jit-access \
	-n jit-system \
	--create-namespace \
	-f ./helm/jit-access/values.example.yaml
```

## CI/CD

- Pipeline: [jit-access-platform-ci.yaml](.github/workflows/jit-access-platform-ci.yaml)
- Semantic release: [semantic-release.yml](.github/workflows/semantic-release.yml)

The CI pipeline builds and pushes the operator image, then updates `.operator.image.tag` in [helm/jit-access/values.yaml](helm/jit-access/values.yaml) to the new release tag.

## Keywords

`zero-trust`, `just-in-time-access`, `kubernetes`, `helm`, `kopf`, `devsecops`, `operator`
