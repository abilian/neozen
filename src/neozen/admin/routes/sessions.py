"""Admin console session management."""

from __future__ import annotations

from litestar import Request, Response, get, post
from litestar.params import FromPath

from neozen.admin.services import AdminService
from neozen.admin.web import (
    ADMIN_ERRORS,
    Page,
    PerPage,
    commit_audited,
    describe_error,
    flash,
    redirect,
    render_template,
)

# -----------------------------------------------------------------------------
# Session Management
# -----------------------------------------------------------------------------


@get("/sessions")
async def list_sessions(
    request: Request, service: AdminService, page: Page = 1, per_page: PerPage = 50
) -> Response:
    """List active sessions, a page at a time."""
    result = await service.list_sessions_with_subjects(page=page, per_page=per_page)
    return render_template(
        request,
        "sessions/list.html",
        {
            "sessions": result.items,
            "page": result.page,
            "per_page": result.per_page,
            "total_items": result.total,
            "total_pages": result.total_pages,
        },
    )


@post("/sessions/{token_hash:str}/revoke")
async def revoke_session(
    request: Request, service: AdminService, token_hash: FromPath[str]
) -> Response:
    """Revoke a session."""
    try:
        await service.revoke_session(token_hash)
        await commit_audited(request, service)
        flash(request, "Session revoked successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error revoking session: {describe_error(e)}", "error")
    return redirect("/sessions")
