# NeoZen — Helm chart

A starter Helm chart for self-hosting NeoZen on Kubernetes. Single
replica, externally-managed PostgreSQL, no horizontal pod autoscaler.
For multi-replica and enterprise-grade deployments, fork and extend.

## Quick install

```bash
# From the repo root
helm install neozen ./deploy/helm \
  --set secrets.secretKey="$(openssl rand -hex 32)" \
  --set secrets.databaseUrl="postgresql+asyncpg://neozen:password@my-postgres:5432/neozen"
```

Then check the bootstrap notice in the pod logs:

```bash
kubectl logs deployment/neozen | grep NEOZEN-BOOTSTRAP-CREDENTIALS -A 6
```

## Production install

For production, create a Secret out-of-band and reference it via
`secrets.existingSecret`:

```bash
kubectl create secret generic neozen-secrets \
  --from-literal=NEOZEN_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=NEOZEN_DATABASE_URL="postgresql+asyncpg://neozen:..."

helm install neozen ./deploy/helm \
  --set secrets.existingSecret=neozen-secrets \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=neozen.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```

## Configuration

See `values.yaml` for the full set of options. Common ones:

| Key | Default | Notes |
|---|---|---|
| `image.repository` | `ghcr.io/abilian/neozen` | Image registry |
| `image.tag` | (chart appVersion) | Image tag |
| `replicaCount` | `1` | Multi-replica is 2.x |
| `service.type` | `ClusterIP` | `LoadBalancer` for direct exposure |
| `ingress.enabled` | `false` | Set to `true` and configure hosts |
| `secrets.existingSecret` | `""` | Name of pre-existing Secret |
| `neozen.bootstrapAdmin` | `true` | Auto-create first admin |
| `neozen.bootstrapAdminEmail` | `admin@localhost` | First admin email |

## What is intentionally missing

This chart is **deliberately small**. The following are not in scope
for the 1.0 reference deployment:

- HorizontalPodAutoscaler — single replica only
- PodDisruptionBudget — single replica
- NetworkPolicies — operator's call
- Bundled PostgreSQL subchart — bring your own database
- ServiceAccount with custom RBAC — uses default
- Cert-manager integration for TLS — annotate Ingress yourself
- Sealed Secrets / SOPS / external-secrets integration

If you need any of these, fork the chart. The starter is meant as
a working baseline, not a finished platform.
