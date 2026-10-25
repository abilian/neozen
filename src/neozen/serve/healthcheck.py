"""Health and readiness endpoints for `neozen serve`.

Two endpoints, following Kubernetes conventions:

- `/healthz`  — liveness. Returns 200 if the process is up.
- `/readyz`   — readiness. Returns 200 if the DB is reachable.

These are intentionally tiny: they exist so container orchestrators
can probe the running service. They are not part of the user-facing
admin or API surface.
"""

from __future__ import annotations

from typing import Any

from litestar import Request, Response, get
from litestar.status_codes import HTTP_503_SERVICE_UNAVAILABLE
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker


@get("/healthz", sync_to_thread=False, exclude_from_auth=True)
def healthz() -> dict[str, Any]:
    """Liveness probe.

    Returns 200 if the process is up. Does not touch the database.
    Use this for `livenessProbe` in Kubernetes — restart on failure.
    """
    return {"status": "ok"}


@get("/readyz", exclude_from_auth=True)
async def readyz(request: Request) -> Response:
    """Readiness probe.

    Returns 200 if the database is reachable, 503 otherwise. Use this
    for `readinessProbe` in Kubernetes — remove from service when not
    ready, but do not restart.
    """
    session_factory: async_sessionmaker = request.app.state.session_factory
    try:
        async with session_factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        return Response(
            content={"status": "unavailable", "error": str(exc)},
            status_code=HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )
    return Response(
        content={"status": "ready"},
        status_code=200,
        media_type="application/json",
    )
