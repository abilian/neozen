"""Admin console audit log."""

from __future__ import annotations

import contextlib

from jinja2 import Environment
from litestar import Request, Response, get
from litestar.params import FromPath

from neozen.admin.services import AdminService
from neozen.admin.web import (
    Page,
    flash,
    redirect,
    render_template,
)

# -----------------------------------------------------------------------------
# Audit Logs
# -----------------------------------------------------------------------------


@get("/audit")
async def list_audit_logs(
    request: Request, service: AdminService, page: Page = 1
) -> Response:
    """List audit logs with filters."""
    # Parse query parameters
    search = request.query_params.get("search")
    event_type = request.query_params.get("event_type")
    action = request.query_params.get("action")
    outcome = request.query_params.get("outcome")
    per_page = 50

    logs = await service.list_audit_logs(
        search=search,
        event_type=event_type,
        action=action,
        outcome=outcome,
        offset=(page - 1) * per_page,
        limit=per_page,
    )
    total = await service.count_audit_logs(
        search=search, event_type=event_type, action=action, outcome=outcome
    )
    event_types, actions = await service.audit_filter_choices()

    # Live tail enabled only when viewing page 1 with no filters.
    # This avoids the polling endpoint clobbering filtered views.
    live_tail = page == 1 and not (search or event_type or action or outcome)

    return render_template(
        request,
        "audit/list.html",
        {
            "logs": logs,
            "search": search,
            "event_type": event_type,
            "action": action,
            "outcome": outcome,
            "event_types": event_types,
            "actions": actions,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total + per_page - 1) // per_page,
            "live_tail": live_tail,
        },
    )


@get("/audit/tail")
async def audit_log_tail(request: Request, service: AdminService) -> Response:
    """HTMX live-tail endpoint for the audit log table.

    Returns just the audit log table partial. The audit list page polls
    this every 10s when viewing page 1 without filters. Always returns
    the most recent N events; ignores filter params (the live tail is
    a fixed view).
    """
    per_page = 50
    logs = await service.list_audit_logs(limit=per_page)
    total = await service.count_audit_logs()

    templates: Environment = request.app.state.templates
    content = templates.get_template("audit/_log_table.html").render(
        logs=logs,
        search=None,
        event_type=None,
        action=None,
        outcome=None,
        page=1,
        per_page=per_page,
        total=total,
        total_pages=1,
        live_tail=True,
    )
    return Response(content=content, media_type="text/html")


@get("/audit/{entry_id:str}")
async def audit_log_detail(
    request: Request, service: AdminService, entry_id: FromPath[str]
) -> Response:
    """View audit log entry details."""
    entry = await service.get_audit_log(entry_id)

    if entry is None:
        flash(request, "Audit log entry not found.", "error")
        return redirect("/audit")

    # Get subject info if available
    subject = None
    if entry.subject_id:
        with contextlib.suppress(Exception):
            subject = await service.get_subject(entry.subject_id)

    # Get actor info if available
    actor = None
    if entry.actor_id:
        with contextlib.suppress(Exception):
            actor = await service.get_subject(entry.actor_id)

    return render_template(
        request,
        "audit/detail.html",
        {
            "entry": entry,
            "subject": subject,
            "actor": actor,
        },
    )
