"""Production composition layer for `neozen serve`.

This package builds a unified Litestar application that exposes the
admin console + health endpoints (and, in a follow-up, the OIDC
provider and SCIM endpoints) under a single entry point. It is the
primary deliverable for the secondary self-hosted-IAM audience —
the path from `pip install neozen` to `docker run abilian/neozen`.

Modules:
- `config`     — `ServeConfig` loaded from env / TOML / CLI
- `bootstrap`  — first-run admin user generation
- `healthcheck`— `/healthz` and `/readyz` endpoints
- `app`        — `build_serve_app(config)` Litestar builder

See `notes/plan/stage17-reference-deployment.md` for the full plan.
"""

from __future__ import annotations

from neozen.serve.app import build_serve_app
from neozen.serve.bootstrap import (
    BOOTSTRAP_NOTICE_BANNER,
    bootstrap_admin_if_needed,
    generate_bootstrap_password,
)
from neozen.serve.config import ServeConfig

__all__ = [
    "BOOTSTRAP_NOTICE_BANNER",
    "ServeConfig",
    "bootstrap_admin_if_needed",
    "build_serve_app",
    "generate_bootstrap_password",
]
