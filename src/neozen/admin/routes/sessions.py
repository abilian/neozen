"""Admin console session management."""

from __future__ import annotations

from litestar import Request, Response, get, post
from litestar.params import FromPath

from neozen.admin.services import AdminService
from neozen.admin.web import (
    ADMIN_ERRORS,
    describe_error,
    flash,
    redirect,
    render_template,
)

# -----------------------------------------------------------------------------
# Session Management
# -----------------------------------------------------------------------------


@get("/sessions")
async def list_sessions(request: Request, service: AdminService) -> Response:
    """List active sessions."""
    sessions_with_subjects = await service.list_sessions_with_subjects()

    return render_template(
        request, "sessions/list.html", {"sessions": sessions_with_subjects}
    )


@post("/sessions/{token_hash:str}/revoke")
async def revoke_session(
    request: Request, service: AdminService, token_hash: FromPath[str]
) -> Response:
    """Revoke a session."""
    try:
        await service.revoke_session(token_hash)
        await service.session.commit()
        flash(request, "Session revoked successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error revoking session: {describe_error(e)}", "error")
    return redirect("/sessions")
