"""Admin console sign-in and sign-out."""

from __future__ import annotations

from litestar import Request, Response, get, post
from pwdlib import PasswordHash

from neozen.admin.auth import (
    ADMIN_SESSION_KEY,
    AdminUser,
    admin_for_subject,
    clear_current_admin,
    set_current_admin,
)
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
from neozen.admin.web import (
    flash,
    redirect,
    render_template,
)
from neozen.storage import DoesNotExist

# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------


_password_hash = PasswordHash.recommended()


async def _authenticate_admin(
    service: AdminService, email: str, password: str, require_role: str
) -> AdminUser | None:
    """Return the admin for valid credentials, or None.

    The subject must exist, be active, have a password that matches, and
    hold a role that grants admin console access (see ``admin_role_for``).
    """
    try:
        subject = await service.subject_repo.get_one_by(email=email)
    except DoesNotExist:
        return None
    if not subject.hashed_password:
        return None
    if not _password_hash.verify(password, subject.hashed_password):
        return None
    return await admin_for_subject(service, subject, require_role)


@get("/login", sync_to_thread=False, exclude_from_auth=True)
def login_page(request: Request) -> Response:
    """Show login page."""
    # If already logged in, redirect to dashboard (the middleware checks it)
    if ADMIN_SESSION_KEY in request.session:
        return redirect("/")
    return render_template(request, "auth/login.html")


@post("/login", exclude_from_auth=True)
async def login(request: Request, service: AdminService) -> Response:
    """Process login form."""
    form_data = await request.form()
    email = form_data.get("email", "").strip()
    password = form_data.get("password", "")
    config: AdminConfig = request.app.state.config

    admin = await _authenticate_admin(service, email, password, config.require_role)

    if admin is None:
        flash(request, "Invalid email or password.", "error")
        return redirect("/login")

    set_current_admin(request, admin)
    flash(request, f"Welcome back, {admin.name}!", "success")
    return redirect("/")


@post("/logout", sync_to_thread=False, exclude_from_auth=True)
def logout(request: Request) -> Response:
    """Log out the current admin user."""
    clear_current_admin(request)
    flash(request, "You have been logged out.", "info")
    return redirect("/login")
