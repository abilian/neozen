"""`neozen serve` — production-mode Litestar entry point.

Boots a unified Litestar application exposing the admin console,
health endpoints, and (in a follow-up) the OIDC provider and SCIM
endpoints. Intended for the secondary self-hosted-IAM audience —
the path from `pip install neozen` to a running container.

This is the CLI front-end. The composition logic lives in
`neozen.serve.app.build_serve_app`.
"""

from __future__ import annotations

import argparse
import sys

from neozen.serve import ServeConfig, build_serve_app


def serve(args: argparse.Namespace) -> int:
    """Run the production server.

    Returns the exit code (0 for clean shutdown, non-zero on error).
    """
    try:
        import uvicorn  # noqa: PLC0415
    except ImportError:
        print(
            "uvicorn is not installed. Install it with "
            "`pip install neozen[demo]` or `pip install uvicorn`.",
            file=sys.stderr,
        )
        return 1

    config = ServeConfig.from_env()

    # CLI flags override env vars
    if getattr(args, "host", None):
        config.bind_host = args.host
    if getattr(args, "port", None):
        config.bind_port = args.port
    if getattr(args, "workers", None):
        config.workers = args.workers
    if getattr(args, "log_level", None):
        config.log_level = args.log_level
    if getattr(args, "no_bootstrap", False):
        config.bootstrap_admin = False

    app = build_serve_app(config)

    print(
        f"[neozen serve] starting on http://{config.bind_host}:{config.bind_port} "
        f"with {config.workers} worker(s)",
        file=sys.stderr,
    )

    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.bind_port,
        workers=config.workers if config.workers > 1 else None,
        log_level=config.log_level.lower(),
    )
    return 0
