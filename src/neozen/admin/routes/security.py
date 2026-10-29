"""Admin console security dashboard."""

from __future__ import annotations

import dataclasses

from jinja2 import Environment
from litestar import Request, Response, get

from neozen.admin.services import AdminService
from neozen.admin.web import (
    render_template,
)

# -----------------------------------------------------------------------------
# Security Dashboard
# -----------------------------------------------------------------------------


@get("/security")
async def security_dashboard(request: Request, service: AdminService) -> Response:
    """Security dashboard with metrics and insights."""

    # Get audit stats
    stats = await service.get_audit_stats(days=7)
    login_activity = await service.get_login_activity(days=7)

    counts = await service.get_security_counts()

    # Recent security events
    recent_events = await service.list_audit_logs(limit=10)

    return render_template(
        request,
        "security/dashboard.html",
        {
            "stats": stats,
            "login_activity": login_activity,
            **dataclasses.asdict(counts),
            "recent_events": recent_events,
        },
    )


@get("/security/stats")
async def security_stats(request: Request, service: AdminService) -> Response:
    """HTMX live-polling endpoint for the security dashboard counters.

    Returns just the security stats partial. The security dashboard
    polls this every 15s.
    """
    stats = await service.get_audit_stats(days=7)
    counts = await service.get_security_counts()

    templates: Environment = request.app.state.templates
    content = templates.get_template("security/_stats.html").render(
        stats=stats,
        **dataclasses.asdict(counts),
        live=True,
    )
    return Response(content=content, media_type="text/html")


@get("/security/policies", sync_to_thread=False)
def security_policies(request: Request) -> Response:
    """Security policy configuration."""
    return render_template(
        request,
        "security/policies.html",
        {},
    )
