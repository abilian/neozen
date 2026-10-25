# NeoZen — Docker deployment

Reference Docker artifacts for self-hosting NeoZen as a unified IAM
service: admin console + health endpoints, with the OIDC provider
and SCIM endpoints to follow in a 1.0 point release.

## Quick start

```bash
# From the repo root
cd deploy/docker
docker compose up -d

# Wait for the bootstrap notice
docker compose logs neozen | grep NEOZEN-BOOTSTRAP-CREDENTIALS -A 6

# Open the admin
open http://localhost:8000/admin
```

The bootstrap admin credentials are printed **once** on first start.
Copy them and change the password on first login. After that they
are not logged or stored in plaintext.

## What you get

- **NeoZen** — the unified Litestar app from `neozen serve`, exposing
  the admin console at `/`, the health endpoints at `/healthz` and
  `/readyz`. (OIDC and SCIM endpoints will mount here in a 1.0 point
  release.)
- **PostgreSQL 16** — persistent database, mounted on a Docker volume.

## Configuration

The compose file accepts these environment variables (with sensible
defaults):

| Variable | Default | Notes |
|---|---|---|
| `POSTGRES_PASSWORD` | `neozen-dev-password` | **Change this in production.** |
| `NEOZEN_SECRET_KEY` | `change-me-in-production` | **Change this in production.** Used for session cookies and token hashing. Set via `.env` or your secret manager. |
| `NEOZEN_BOOTSTRAP_ADMIN_EMAIL` | `admin@localhost` | Email for the bootstrap admin user. |

For production deployments, create a `.env` file alongside this
README:

```bash
NEOZEN_SECRET_KEY=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 32)
```

## Building manually

If you don't want to use compose, build and run the image directly:

```bash
# From the repo root
docker build -t neozen:dev -f deploy/docker/Dockerfile .

docker run --rm -p 8000:8000 \
  -e NEOZEN_SECRET_KEY=$(openssl rand -hex 32) \
  -e NEOZEN_DATABASE_URL=sqlite+aiosqlite:///data/neozen.db \
  -v neozen-data:/home/neozen/data \
  neozen:dev
```

## Production hardening

The reference compose file is designed for "small team self-hosted"
deployments — single replica, embedded Postgres, no TLS termination.
For production use:

- **TLS** — terminate TLS at an external reverse proxy (nginx, traefik,
  ingress controller). NeoZen does not handle TLS itself.
- **Proxy address** — set `FORWARDED_ALLOW_IPS` to the reverse proxy's address so uvicorn trusts its `X-Forwarded-For`. Rate limits and lockout are keyed on the client address; without this, every client shares the proxy's.
- **External Postgres** — point `NEOZEN_DATABASE_URL` at a managed
  Postgres instance and remove the `postgres` service from compose.
- **Secrets** — use `NEOZEN_SECRET_KEY_FILE` and similar `_FILE` variants
  to read from Docker secrets / Kubernetes secret mounts instead of
  environment variables.
- **Backups** — back up the Postgres volume on a schedule. NeoZen has
  no opinion on how.
- **Monitoring** — `/healthz` is liveness, `/readyz` is readiness.
  Wire both into your orchestrator.

For a Kubernetes deployment, see `deploy/helm/`.
