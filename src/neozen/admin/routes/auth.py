"""Admin console sign-in and sign-out."""

from __future__ import annotations

import anyio.to_thread
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
from neozen.core.security import RateLimiter
from neozen.ext.litestar.rate_limit import get_client_ip
from neozen.storage import DoesNotExist

# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------


_password_hash = PasswordHash.recommended()
# Checked when the email is unknown, so every failed login costs one hash
# and its timing doesn't reveal which accounts exist.
_DUMMY_HASH = _password_hash.hash("not a real password")


async def _password_matches(password: str, hashed: str | None) -> bool:
    """Argon2 check, off the event loop: it takes tens of milliseconds."""
    matches = await anyio.to_thread.run_sync(
        _password_hash.verify, password, hashed or _DUMMY_HASH
    )
    return matches and hashed is not None


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
        subject = None
    hashed = subject.hashed_password if subject else None
    if not await _password_matches(password, hashed) or subject is None:
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
    limiter: RateLimiter = request.app.state.login_limiter
    key = limiter.make_key(
        ip_address=get_client_ip(request.scope),
        subject_id=email.lower(),
        action="admin_login",
    )
    if not (await limiter.check(key)).allowed:
        flash(request, "Too many failed sign-ins. Try again later.", "error")
        return redirect("/login")

    admin = await _authenticate_admin(service, email, password, config.require_role)
    await limiter.record_attempt(key, success=admin is not None)

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
