# Self-Hosted Quickstart

**Audience**: a small team that wants to run NeoZen as a standalone
IAM service that other apps talk to over OIDC, with an admin
console for day-to-day user management.

**Goal**: a working self-hosted IAM in under 10 minutes.

If instead you want to embed NeoZen as a library inside your own
Python app, see the [Developer Quickstart](quickstart.md).

!!! note "What ships in 0.9"

    The 0.9 reference deployment exposes the **admin console** plus
    `/healthz` and `/readyz` health endpoints. The OIDC provider and
    SCIM endpoints already exist in the codebase but mounting them
    into the unified `neozen serve` Litestar app is scheduled for a
    later 0.x point release. The library half (embed via
    `pip install`) has full OIDC and SCIM support today.

---

## 1. Prerequisites

- Docker (Docker Desktop, Colima, Podman, etc.)
- 5 minutes

You don't need to install Python, set up a database or create the
schema.

## 2. Boot the stack

Run this from a clone of the NeoZen repository:

```bash
cd deploy/docker
docker compose up -d
```

This brings up two containers:

- **`postgres`**: PostgreSQL 16 with a persistent named volume
- **`neozen`**: the NeoZen `serve` app on port `8000`

Wait for the healthchecks to pass (usually ~10 seconds):

```bash
docker compose ps
# STATUS should show (healthy) for both services
```

## 3. Find the bootstrap admin password

NeoZen prints a one-time admin password on first start. Grep
for it:

```bash
docker compose logs neozen | grep NEOZEN-BOOTSTRAP-CREDENTIALS -A 6
```

You'll see something like:

```
======================================================================
  NEOZEN-BOOTSTRAP-CREDENTIALS
======================================================================
  email:    admin@localhost
  password: gK7xQ2pN9LmBvYwFh4tRcWzA

  This password is shown ONCE. Copy it now and change it
  on first login. It is not logged or stored in plain text.
======================================================================
```

**Copy this password now**. It's not stored anywhere else, and the
banner only fires the first time the database is empty.

## 4. Open the admin console

Browse to <http://localhost:8000/login> and sign in with
`admin@localhost` and the password you just copied.

You should land on the dashboard. From here you can:

- Create users
- Bulk-import users from CSV
- Manage roles and permissions
- View audit logs (with live updates)
- Configure security policies

## 5. Stop and restart

```bash
docker compose stop      # stops the containers, keeps the data
docker compose start     # starts them again
docker compose down      # stops and removes the containers (data persists in the volume)
docker compose down -v   # ALSO removes the database volume — clean slate
```

The PostgreSQL data lives in a Docker named volume, so
`stop` / `start` is safe. Only `down -v` wipes the data.

---

## Production hardening

The reference compose file is designed for "small team self-hosted"
deployments: a single replica, embedded Postgres, and no TLS termination.
For production:

### TLS

Terminate TLS at an external reverse proxy (nginx, traefik, ingress
controller). NeoZen does not handle TLS itself.

Set `FORWARDED_ALLOW_IPS` to the proxy's address (uvicorn reads it from the environment). NeoZen keys rate limits and account lockout on the client address, and only trusts `X-Forwarded-For` from those IPs; without it, every client shares the proxy's address.

### Real secret key

Replace `change-me-in-production` with a real secret key:

```bash
openssl rand -hex 32 > .env.secret
# Then in deploy/docker/.env:
echo "NEOZEN_SECRET_KEY=$(cat .env.secret)" >> .env
echo "POSTGRES_PASSWORD=$(openssl rand -hex 32)" >> .env
```

The compose file reads `.env` automatically.

### External Postgres

In production, point at a managed Postgres instance and remove the
`postgres` service from compose:

```yaml
services:
  neozen:
    environment:
      NEOZEN_DATABASE_URL: postgresql+asyncpg://user:pass@db.example.com:5432/neozen
```

### Secrets via files

For Docker secrets / Kubernetes secret mounts, use the `_FILE`
variant of any environment variable:

```yaml
environment:
  NEOZEN_SECRET_KEY_FILE: /run/secrets/neozen_secret_key
  NEOZEN_DATABASE_URL_FILE: /run/secrets/neozen_db_url
```

### Backups

Back up the Postgres volume on a schedule. NeoZen has no opinion
on how: `pg_dump`, Postgres replication and snapshots all work.

### Monitoring

The serve app exposes two health endpoints:

- `GET /healthz`: liveness. Returns 200 if the process is up.
- `GET /readyz`: readiness. Returns 200 if the database is reachable.

Wire both into your orchestrator. Restart on `/healthz` failure;
remove from service rotation on `/readyz` failure.

---

## Kubernetes (Helm)

A starter Helm chart ships in `deploy/helm/`:

```bash
helm install neozen ./deploy/helm \
  --set secrets.secretKey="$(openssl rand -hex 32)" \
  --set secrets.databaseUrl="postgresql+asyncpg://neozen:password@my-postgres:5432/neozen"

kubectl logs deployment/neozen | grep NEOZEN-BOOTSTRAP-CREDENTIALS -A 6
```

The chart is minimal: a single replica and an externally managed
PostgreSQL, without autoscaling or network policies. See
`deploy/helm/README.md` for the full configuration reference and for
what the chart leaves out.

For production, create a Secret out-of-band and reference it via
`secrets.existingSecret`:

```bash
kubectl create secret generic neozen-secrets \
  --from-literal=NEOZEN_SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=NEOZEN_DATABASE_URL="postgresql+asyncpg://..."

helm install neozen ./deploy/helm \
  --set secrets.existingSecret=neozen-secrets \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=neozen.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```

---

## Migrations

The reference deployment runs the schema baseline automatically on
first start. For schema upgrades on existing databases:

```bash
# Inside the container
docker compose exec neozen alembic upgrade head

# Or from a clone of the repo (with NEOZEN_DATABASE_URL set)
NEOZEN_DATABASE_URL="postgresql+asyncpg://..." uv run alembic upgrade head
```

The Alembic environment automatically translates async-driver URLs
(`postgresql+asyncpg://`, `sqlite+aiosqlite://`) to their sync
equivalents, so the same `NEOZEN_DATABASE_URL` works for both the
running application and the migration tooling.

---

## Configuration reference

| Environment variable | Default | Notes |
|---|---|---|
| `NEOZEN_DATABASE_URL` | `sqlite+aiosqlite:///data/neozen.db` | Async SQLAlchemy URL. The `_FILE` variant reads from a file. |
| `NEOZEN_SECRET_KEY` | `change-me-in-production` | **Required in production**. Used for session HMAC and token hashing. The `_FILE` variant reads from a file. |
| `NEOZEN_BIND_HOST` | `0.0.0.0` | Bind interface for the HTTP server. |
| `NEOZEN_BIND_PORT` | `8000` | Bind port. |
| `NEOZEN_WORKERS` | `1` | Uvicorn worker processes. Multi-replica is deferred to a future enterprise-focused release. |
| `NEOZEN_LOG_LEVEL` | `INFO` | Standard Python log levels. |
| `NEOZEN_BOOTSTRAP_ADMIN` | `true` | If true and the database is empty, create a bootstrap admin and print the credentials once. |
| `NEOZEN_BOOTSTRAP_ADMIN_EMAIL` | `admin@localhost` | Email for the bootstrap admin. |
| `NEOZEN_COOKIE_SECURE` | `true` | Secure flag on the admin session cookie. Set `false` only when serving over plain HTTP from a host other than `localhost` (browsers accept Secure cookies on `http://localhost`, except Safari). |

CLI flags override environment variables:

```bash
neozen serve --host 127.0.0.1 --port 9000 --workers 4 --log-level debug --no-bootstrap
```

---

## Where to go next

- [Configuration reference](../reference/configuration.md): full
  config schema (TOML + env vars)
- [Authorization (RBAC)](../guides/authorization.md): roles and
  permissions
- [SCIM 2.0](../guides/scim.md): provisioning users and groups
  from an upstream IdP (currently library-only; mounting under
  `neozen serve` is a later 0.x follow-up)
- [LDAP backend](../guides/ldap.md): authenticate against a
  corporate LDAP/Active Directory directory
