"""Admin console dashboard."""

from __future__ import annotations

from jinja2 import Environment
from litestar import Request, Response, get

from neozen.admin.services import AdminService, UserListFilters
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
    newest = await service.list_subjects_paginated(
        UserListFilters(sort_by="created_at", sort_order="desc", per_page=5)
    )
    recent_users = newest.items
    stats_dict = {
        "total_users": stats.total_subjects,
        "active_sessions": stats.active_sessions,
        "total_roles": stats.total_roles,
        "total_assignments": stats.role_assignments,
    }
    recent_activity = await service.list_audit_logs(limit=5)

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
