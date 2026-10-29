"""Admin console dashboard."""

from __future__ import annotations

from typing import Any

from jinja2 import Environment
from litestar import Request, Response, get

from neozen.admin.services import AdminService
from neozen.admin.web import (
    render_template,
)

# -----------------------------------------------------------------------------
# Dashboard
# -----------------------------------------------------------------------------


@get("/")
async def dashboard(request: Request, service: AdminService) -> Response:
    """Admin dashboard with statistics."""
    stats = await service.get_dashboard_stats()
    recent_users = await service.list_subjects(limit=5)

    # Prepare stats dict for new template
    stats_dict = {
        "total_users": stats.total_subjects,
        "active_sessions": stats.active_sessions,
        "total_roles": stats.total_roles,
        "total_assignments": stats.total_subjects,  # Placeholder
    }

    # Recent activity placeholder (would come from audit log)
    recent_activity: list[dict[str, Any]] = []

    return render_template(
        request,
        "dashboard/index.html",
        {
            "stats": stats_dict,
            "recent_users": recent_users,
            "recent_activity": recent_activity,
        },
    )


@get("/dashboard/stats")
async def dashboard_stats(request: Request, service: AdminService) -> Response:
    """HTMX live-polling endpoint for the main dashboard counters.

    Returns just the dashboard stats partial. The dashboard polls
    this every 15s.
    """
    stats = await service.get_dashboard_stats()

    stats_dict = {
        "total_users": stats.total_subjects,
        "active_sessions": stats.active_sessions,
        "total_roles": stats.total_roles,
        "total_assignments": stats.total_subjects,
    }

    templates: Environment = request.app.state.templates
    content = templates.get_template("dashboard/_stats.html").render(
        stats=stats_dict,
        live=True,
    )
    return Response(content=content, media_type="text/html")
