"""Admin UI Litestar application.

Enterprise-grade admin console built with HTMX + Alpine.js + Tailwind CSS.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from litestar import Litestar, Request, Response, get, post
from litestar.datastructures import State
from litestar.exceptions import NotAuthorizedException
from litestar.middleware import DefineMiddleware
from litestar.params import FromPath
from litestar.status_codes import HTTP_303_SEE_OTHER
from markupsafe import escape
from pwdlib import PasswordHash
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from neozen.admin.auth import (
    ADMIN_SESSION_KEY,
    AdminAuthMiddleware,
    AdminUser,
    RotatingSessionConfig,
    admin_for_subject,
    clear_current_admin,
    get_current_admin,
    get_impersonation,
    redirect_to_login_handler,
    set_current_admin,
    start_impersonation,
    stop_impersonation,
)
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService, UserListFilters
from neozen.storage import DoesNotExist
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.models import RoleAssignment, Session, Subject

# Template directory
TEMPLATES_DIR = Path(__file__).parent / "templates"


def get_templates(config: AdminConfig) -> Environment:
    """Create Jinja2 environment with component macros."""
    templates_dir = config.templates_dir or TEMPLATES_DIR
    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)
    return env


def render_template(
    request: Request,
    template_name: str,
    context: dict[str, Any] | None = None,
    status_code: int = 200,
) -> Response:
    """Render a Jinja2 template."""
    templates: Environment = request.app.state.templates
    ctx = context or {}
    ctx["messages"] = request.session.pop("messages", [])
    ctx["request"] = request
    ctx["current_admin"] = get_current_admin(request)
    ctx["impersonation"] = get_impersonation(request)
    content = templates.get_template(template_name).render(**ctx)
    return Response(content=content, status_code=status_code, media_type="text/html")


def flash(request: Request, message: str, category: str = "info") -> None:
    """Add a flash message to the session."""
    messages = request.session.get("messages", [])
    messages.append((category, message))
    request.session["messages"] = messages


def redirect(url: str) -> Response:
    """Create a redirect response."""
    return Response(
        content=None,
        status_code=HTTP_303_SEE_OTHER,
        headers={"Location": url},
    )


async def get_admin_service(request: Request) -> AsyncGenerator[AdminService, None]:
    """Get admin service with database session."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        yield AdminService(session)


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
async def login(request: Request) -> Response:
    """Process login form."""
    form_data = await request.form()
    email = form_data.get("email", "").strip()
    password = form_data.get("password", "")
    config: AdminConfig = request.app.state.config

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        admin = await _authenticate_admin(
            AdminService(session), email, password, config.require_role
        )

    if admin is None:
        flash(request, "Invalid email or password.", "error")
        return redirect("/login")

    set_current_admin(request, admin)
    flash(request, f"Welcome back, {admin.name}!", "success")
    return redirect("/")


@get("/logout", sync_to_thread=False, exclude_from_auth=True)
def logout(request: Request) -> Response:
    """Log out the current admin user."""
    clear_current_admin(request)
    flash(request, "You have been logged out.", "info")
    return redirect("/login")


# -----------------------------------------------------------------------------
# Dashboard
# -----------------------------------------------------------------------------


@get("/")
async def dashboard(request: Request) -> Response:
    """Admin dashboard with statistics."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
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
async def dashboard_stats(request: Request) -> Response:
    """HTMX live-polling endpoint for the main dashboard counters.

    Returns just the dashboard stats partial. The dashboard polls
    this every 15s.
    """
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
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


# -----------------------------------------------------------------------------
# User Management (formerly Subject Management)
# -----------------------------------------------------------------------------


@get("/users")
async def list_users(request: Request) -> Response:
    """List all users with search, filters, and pagination."""
    # Parse query parameters
    search = request.query_params.get("search")
    status = request.query_params.get("status")
    mfa = request.query_params.get("mfa")
    verified = request.query_params.get("verified")
    sort_by = request.query_params.get("sort", "created_at")
    sort_order = request.query_params.get("order", "desc")
    page = int(request.query_params.get("page", "1"))
    per_page = int(request.query_params.get("per_page", "50"))

    # Build filters
    status_list = [status] if status else None
    filters = UserListFilters(
        search=search,
        status=status_list,
        mfa_enabled=mfa == "enabled" if mfa else None,
        is_verified=verified == "yes" if verified else None,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        result = await service.list_subjects_paginated(filters)

        return render_template(
            request,
            "users/list.html",
            {
                "users": result.items,
                "search": search,
                "status": status,
                "mfa": mfa,
                "verified": verified,
                "sort": sort_by,
                "order": sort_order,
                "page": result.page,
                "per_page": result.per_page,
                "total_items": result.total,
                "total_pages": result.total_pages,
            },
        )


@get("/users/{user_id:str}")
async def user_detail(request: Request, user_id: FromPath[str]) -> Response:
    """View user details with tabs."""
    tab = request.query_params.get("tab", "profile")
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            user = await service.get_subject(user_id)
            roles = await service.get_subject_roles(user_id)
            sessions = await service.get_subject_sessions(user_id, active_only=True)
            all_roles = await service.list_roles()

            return render_template(
                request,
                "users/detail.html",
                {
                    "user": user,
                    "roles": roles,
                    "sessions": sessions,
                    "all_roles": all_roles,
                    "active_tab": tab,
                },
            )
        except Exception:
            flash(request, f"User not found: {user_id}", "error")
            return redirect("/users")


@post("/users/{user_id:str}/activate")
async def activate_user(request: Request, user_id: FromPath[str]) -> Response:
    """Activate a user."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.activate_subject(user_id)
            await session.commit()
            flash(request, "User activated successfully.", "success")
        except Exception as e:
            flash(request, f"Error activating user: {e}", "error")
        return redirect(f"/users/{user_id}")


@post("/users/{user_id:str}/deactivate")
async def deactivate_user(request: Request, user_id: FromPath[str]) -> Response:
    """Deactivate a user."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.deactivate_subject(user_id)
            await session.commit()
            flash(request, "User deactivated successfully.", "success")
        except Exception as e:
            flash(request, f"Error deactivating user: {e}", "error")
        return redirect(f"/users/{user_id}")


@get("/users/create", sync_to_thread=False)
def create_user_form(request: Request) -> Response:
    """Show create user form."""
    return render_template(request, "users/create.html", {})


@post("/users/create")
async def create_user(request: Request) -> Response:
    """Create a new user."""
    form_data = await request.form()
    email = form_data.get("email", "").strip()
    username = form_data.get("username", "").strip() or None

    if not email:
        flash(request, "Email is required.", "error")
        return redirect("/users/create")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            user = await service.create_subject(
                email=email,
                username=username,
                is_active=form_data.get("is_active") == "on",
                is_verified=form_data.get("is_verified") == "on",
            )
            await session.commit()
            flash(request, f"User '{email}' created successfully.", "success")
            return redirect(f"/users/{user.id}")
        except Exception as e:
            flash(request, f"Error creating user: {e}", "error")
            return redirect("/users/create")


@post("/users/{user_id:str}/delete")
async def delete_user(request: Request, user_id: FromPath[str]) -> Response:
    """Delete a user."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.delete_subject(user_id)
            await session.commit()
            flash(request, "User deleted successfully.", "success")
        except Exception as e:
            flash(request, f"Error deleting user: {e}", "error")
        return redirect("/users")


@post("/users/{user_id:str}/revoke-sessions")
async def revoke_user_sessions(request: Request, user_id: FromPath[str]) -> Response:
    """Revoke all sessions for a user."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            count = await service.revoke_all_subject_sessions(user_id)
            await session.commit()
            flash(request, f"Revoked {count} session(s) successfully.", "success")
        except Exception as e:
            flash(request, f"Error revoking sessions: {e}", "error")
        return redirect(f"/users/{user_id}?tab=sessions")


@post("/users/{user_id:str}/roles/add")
async def add_user_role(request: Request, user_id: FromPath[str]) -> Response:
    """Add a role to a user."""
    form_data = await request.form()
    role_name = form_data.get("role_name", "").strip()

    if not role_name:
        flash(request, "Role name is required.", "error")
        return redirect(f"/users/{user_id}?tab=roles")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        admin = get_current_admin(request)
        try:
            await service.assign_role_to_subject(
                user_id, role_name, granted_by=admin.id if admin else None
            )
            await session.commit()
            flash(request, f"Role '{role_name}' assigned successfully.", "success")
        except Exception as e:
            flash(request, f"Error assigning role: {e}", "error")
        return redirect(f"/users/{user_id}?tab=roles")


@post("/users/{user_id:str}/roles/{role_name:str}/remove")
async def remove_user_role(
    request: Request, user_id: FromPath[str], role_name: FromPath[str]
) -> Response:
    """Remove a role from a user."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.remove_role_from_subject(user_id, role_name)
            await session.commit()
            flash(request, f"Role '{role_name}' removed successfully.", "success")
        except Exception as e:
            flash(request, f"Error removing role: {e}", "error")
        return redirect(f"/users/{user_id}?tab=roles")


@get("/users/import", sync_to_thread=False)
def import_users_form(request: Request) -> Response:
    """Show bulk import form."""
    return render_template(request, "users/import.html", {"result": None})


@post("/users/import")
async def import_users(request: Request) -> Response:
    """Process bulk user import from CSV via the bulk-ops module.

    Supports two modes via the form's `action` field:
    - `dry_run`: parse + validate, show preview, do not commit
    - `apply`: parse + validate + commit

    The `update_existing` checkbox toggles update vs skip semantics for
    rows whose email matches an existing user.
    """
    from neozen.admin.bulk import import_subjects_from_csv  # noqa: PLC0415

    form_data = await request.form()
    csv_file = form_data.get("csv_file")
    action = (form_data.get("action") or "dry_run").strip()
    update_existing = bool(form_data.get("update_existing"))

    if not csv_file or not hasattr(csv_file, "read"):
        flash(request, "Please upload a CSV file.", "error")
        return redirect("/users/import")

    try:
        content = (await csv_file.read()).decode("utf-8")
    except UnicodeDecodeError:
        flash(request, "Could not decode CSV: file is not UTF-8.", "error")
        return redirect("/users/import")

    dry_run = action != "apply"
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        result = await import_subjects_from_csv(
            service,
            content,
            dry_run=dry_run,
            update_existing=update_existing,
        )
        if not dry_run:
            await session.commit()

    if dry_run:
        if result.has_failures:
            flash(
                request,
                f"Dry run: {result.failed} row(s) would fail. "
                "Review the preview before applying.",
                "error",
            )
        else:
            flash(
                request,
                f"Dry run OK: {result.created} to create, "
                f"{result.updated} to update, {result.skipped} to skip.",
                "success",
            )
    else:
        msg_parts = []
        if result.created:
            msg_parts.append(f"created {result.created}")
        if result.updated:
            msg_parts.append(f"updated {result.updated}")
        if result.skipped:
            msg_parts.append(f"skipped {result.skipped}")
        if result.failed:
            msg_parts.append(f"failed {result.failed}")
        category = "error" if result.has_failures else "success"
        flash(
            request,
            "Import done: " + ", ".join(msg_parts) if msg_parts else "Import done.",
            category,
        )

    return render_template(
        request,
        "users/import.html",
        {
            "result": result,
            "update_existing": update_existing,
        },
    )


@get("/users/export")
async def export_users(request: Request) -> Response:
    """Export all subjects as CSV."""
    from neozen.admin.bulk import export_subjects_to_csv  # noqa: PLC0415

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        csv_text = await export_subjects_to_csv(service)

    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="neozen-users.csv"',
        },
    )


@post("/users/{user_id:str}/impersonate")
async def impersonate_user(request: Request, user_id: FromPath[str]) -> Response:
    """Start impersonating a user."""
    admin = get_current_admin(request)
    if not admin or not admin.is_superadmin:
        flash(request, "Only superadmins can impersonate users.", "error")
        return redirect(f"/users/{user_id}")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            user = await service.get_subject(user_id)
            start_impersonation(request, user.id, user.email, user.username)
            flash(
                request,
                f"Now impersonating {user.email}. Click 'Stop Impersonation' to return.",
                "success",
            )
        except Exception as e:
            flash(request, f"Error starting impersonation: {e}", "error")
        return redirect(f"/users/{user_id}")


@post("/stop-impersonation", sync_to_thread=False)
def end_impersonation(request: Request) -> Response:
    """Stop impersonating a user."""
    stop_impersonation(request)
    flash(request, "Stopped impersonation.", "success")
    return redirect("/")


# Legacy routes for backwards compatibility
@get("/subjects", sync_to_thread=False)
def list_subjects(request: Request) -> Response:
    """Redirect to users list."""
    return redirect("/users")


# -----------------------------------------------------------------------------
# Role Management
# -----------------------------------------------------------------------------


@get("/roles")
async def list_roles(request: Request) -> Response:
    """List all roles."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        roles = await service.list_roles()
        return render_template(request, "roles/list.html", {"roles": roles})


@get("/roles/create", sync_to_thread=False)
def create_role_form(request: Request) -> Response:
    """Show create role form."""
    return render_template(request, "roles/create.html", {})


@post("/roles/create")
async def create_role(request: Request) -> Response:
    """Create a new role."""
    form_data = await request.form()
    name = form_data.get("name", "").strip()
    description = form_data.get("description", "").strip()
    permissions_str = form_data.get("permissions", "").strip()

    if not name:
        flash(request, "Role name is required.", "error")
        return redirect("/roles/create")

    permissions = [p.strip() for p in permissions_str.split(",") if p.strip()]
    if not permissions:
        flash(request, "At least one permission is required.", "error")
        return redirect("/roles/create")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.create_role(name, permissions, description)
            await session.commit()
            flash(request, f"Role '{name}' created successfully.", "success")
            return redirect("/roles")
        except Exception as e:
            flash(request, f"Error creating role: {e}", "error")
            return redirect("/roles/create")


@get("/roles/{role_name:str}")
async def role_detail(request: Request, role_name: FromPath[str]) -> Response:
    """View role details."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            role = await service.get_role(role_name)
            assignments = await service.get_role_assignments(role_name)
        except Exception:
            flash(request, f"Role not found: {role_name}", "error")
            return redirect("/roles")

        assignments_with_subjects = await _resolve_assignment_subjects(
            service, assignments
        )
        return render_template(
            request,
            "roles/detail.html",
            {
                "role": role,
                "assignments": assignments_with_subjects,
            },
        )


async def _resolve_assignment_subjects(
    service: AdminService,
    assignments: list[RoleAssignment],
) -> list[tuple[RoleAssignment, Subject | None]]:
    """Map each role assignment to ``(assignment, subject_or_None)``.

    Lookup failures collapse to ``None`` so an orphan FK doesn't break
    the page render.
    """
    result: list[tuple[RoleAssignment, Subject | None]] = []
    for assignment in assignments:
        try:
            subject = await service.get_subject(assignment.subject_id)
        except Exception:
            subject = None
        result.append((assignment, subject))
    return result


@post("/roles/{role_name:str}/delete")
async def delete_role(request: Request, role_name: FromPath[str]) -> Response:
    """Delete a role."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.delete_role(role_name)
            await session.commit()
            flash(request, f"Role '{role_name}' deleted successfully.", "success")
        except Exception as e:
            flash(request, f"Error deleting role: {e}", "error")
        return redirect("/roles")


# -----------------------------------------------------------------------------
# Session Management
# -----------------------------------------------------------------------------


@get("/sessions")
async def list_sessions(request: Request) -> Response:
    """List active sessions."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        sessions = await service.list_sessions(active_only=True)

        # Get subject info for each session
        sessions_with_subjects: list[tuple[Session, Subject | None]] = []
        for sess in sessions:
            try:
                subject = await service.get_subject(sess.subject_id)
                sessions_with_subjects.append((sess, subject))
            except Exception:
                sessions_with_subjects.append((sess, None))

        return render_template(
            request, "sessions/list.html", {"sessions": sessions_with_subjects}
        )


@post("/sessions/{token_hash:str}/revoke")
async def revoke_session(request: Request, token_hash: FromPath[str]) -> Response:
    """Revoke a session."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.revoke_session(token_hash)
            await session.commit()
            flash(request, "Session revoked successfully.", "success")
        except Exception as e:
            flash(request, f"Error revoking session: {e}", "error")
        return redirect("/sessions")


# -----------------------------------------------------------------------------
# Group Management
# -----------------------------------------------------------------------------


@get("/groups")
async def list_groups(request: Request) -> Response:
    """List all groups."""
    search = request.query_params.get("search")
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        groups = await service.list_groups(search=search)
        return render_template(
            request, "groups/list.html", {"groups": groups, "search": search}
        )


@get("/groups/create", sync_to_thread=False)
def create_group_form(request: Request) -> Response:
    """Show create group form."""
    return render_template(request, "groups/create.html", {})


@post("/groups/create")
async def create_group(request: Request) -> Response:
    """Create a new group."""
    form_data = await request.form()
    name = form_data.get("name", "").strip()
    description = form_data.get("description", "").strip()

    if not name:
        flash(request, "Group name is required.", "error")
        return redirect("/groups/create")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            group = await service.create_group(name=name, description=description)
            await session.commit()
            flash(request, f"Group '{name}' created successfully.", "success")
            return redirect(f"/groups/{group.id}")
        except Exception as e:
            flash(request, f"Error creating group: {e}", "error")
            return redirect("/groups/create")


@get("/groups/{group_id:str}")
async def group_detail(request: Request, group_id: FromPath[str]) -> Response:
    """View group details."""
    tab = request.query_params.get("tab", "members")
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            group = await service.get_group(group_id)
            members = await service.get_group_members(group_id)
            roles = await service.get_group_roles(group_id)
            all_roles = await service.list_roles()
            all_users = await service.list_subjects(limit=100)

            return render_template(
                request,
                "groups/detail.html",
                {
                    "group": group,
                    "members": members,
                    "roles": roles,
                    "all_roles": all_roles,
                    "all_users": all_users,
                    "active_tab": tab,
                },
            )
        except Exception:
            flash(request, f"Group not found: {group_id}", "error")
            return redirect("/groups")


@post("/groups/{group_id:str}/members/add")
async def add_group_member(request: Request, group_id: FromPath[str]) -> Response:
    """Add a member to a group."""
    form_data = await request.form()
    subject_id = form_data.get("subject_id", "").strip()
    role = form_data.get("role", "member").strip()

    if not subject_id:
        flash(request, "User is required.", "error")
        return redirect(f"/groups/{group_id}?tab=members")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        admin = get_current_admin(request)
        try:
            await service.add_group_member(
                group_id, subject_id, role=role, added_by=admin.id if admin else None
            )
            await session.commit()
            flash(request, "Member added successfully.", "success")
        except Exception as e:
            flash(request, f"Error adding member: {e}", "error")
        return redirect(f"/groups/{group_id}?tab=members")


@post("/groups/{group_id:str}/members/{subject_id:str}/remove")
async def remove_group_member(
    request: Request, group_id: FromPath[str], subject_id: FromPath[str]
) -> Response:
    """Remove a member from a group."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.remove_group_member(group_id, subject_id)
            await session.commit()
            flash(request, "Member removed successfully.", "success")
        except Exception as e:
            flash(request, f"Error removing member: {e}", "error")
        return redirect(f"/groups/{group_id}?tab=members")


@post("/groups/{group_id:str}/roles/add")
async def add_group_role(request: Request, group_id: FromPath[str]) -> Response:
    """Add a role to a group."""
    form_data = await request.form()
    role_name = form_data.get("role_name", "").strip()

    if not role_name:
        flash(request, "Role is required.", "error")
        return redirect(f"/groups/{group_id}?tab=roles")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        admin = get_current_admin(request)
        try:
            await service.assign_role_to_group(
                group_id, role_name, granted_by=admin.id if admin else None
            )
            await session.commit()
            flash(request, f"Role '{role_name}' assigned to group.", "success")
        except Exception as e:
            flash(request, f"Error assigning role: {e}", "error")
        return redirect(f"/groups/{group_id}?tab=roles")


@post("/groups/{group_id:str}/roles/{role_name:str}/remove")
async def remove_group_role(
    request: Request, group_id: FromPath[str], role_name: FromPath[str]
) -> Response:
    """Remove a role from a group."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.remove_role_from_group(group_id, role_name)
            await session.commit()
            flash(request, f"Role '{role_name}' removed from group.", "success")
        except Exception as e:
            flash(request, f"Error removing role: {e}", "error")
        return redirect(f"/groups/{group_id}?tab=roles")


@post("/groups/{group_id:str}/delete")
async def delete_group(request: Request, group_id: FromPath[str]) -> Response:
    """Delete a group."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.delete_group(group_id)
            await session.commit()
            flash(request, "Group deleted successfully.", "success")
        except Exception as e:
            flash(request, f"Error deleting group: {e}", "error")
        return redirect("/groups")


# -----------------------------------------------------------------------------
# Organization Management
# -----------------------------------------------------------------------------


@get("/organizations")
async def list_organizations(request: Request) -> Response:
    """List all organizations."""
    search = request.query_params.get("search")
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        organizations = await service.list_organizations(search=search)
        return render_template(
            request,
            "organizations/list.html",
            {"organizations": organizations, "search": search},
        )


@get("/organizations/create", sync_to_thread=False)
def create_organization_form(request: Request) -> Response:
    """Show create organization form."""
    return render_template(request, "organizations/create.html", {})


@post("/organizations/create")
async def create_organization(request: Request) -> Response:
    """Create a new organization."""
    form_data = await request.form()
    name = form_data.get("name", "").strip()
    slug = form_data.get("slug", "").strip()
    domain = form_data.get("domain", "").strip() or None
    plan = form_data.get("plan", "free").strip()

    if not name or not slug:
        flash(request, "Name and slug are required.", "error")
        return redirect("/organizations/create")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            org = await service.create_organization(
                name=name, slug=slug, domain=domain, plan=plan
            )
            await session.commit()
            flash(request, f"Organization '{name}' created successfully.", "success")
            return redirect(f"/organizations/{org.id}")
        except Exception as e:
            flash(request, f"Error creating organization: {e}", "error")
            return redirect("/organizations/create")


@get("/organizations/{org_id:str}")
async def organization_detail(request: Request, org_id: FromPath[str]) -> Response:
    """View organization details."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            org = await service.get_organization(org_id)
            # Get groups for this organization
            all_groups = await service.list_groups()
            org_groups = [g for g in all_groups if g.organization_id == org_id]

            return render_template(
                request,
                "organizations/detail.html",
                {
                    "organization": org,
                    "groups": org_groups,
                },
            )
        except Exception:
            flash(request, f"Organization not found: {org_id}", "error")
            return redirect("/organizations")


@post("/organizations/{org_id:str}/update")
async def update_organization(request: Request, org_id: FromPath[str]) -> Response:
    """Update an organization."""
    form_data = await request.form()
    name = form_data.get("name", "").strip() or None
    domain = form_data.get("domain", "").strip() or None
    plan = form_data.get("plan", "").strip() or None
    is_active = form_data.get("is_active") == "on"

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.update_organization(
                org_id, name=name, domain=domain, plan=plan, is_active=is_active
            )
            await session.commit()
            flash(request, "Organization updated successfully.", "success")
        except Exception as e:
            flash(request, f"Error updating organization: {e}", "error")
        return redirect(f"/organizations/{org_id}")


@post("/organizations/{org_id:str}/delete")
async def delete_organization(request: Request, org_id: FromPath[str]) -> Response:
    """Delete an organization."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.delete_organization(org_id)
            await session.commit()
            flash(request, "Organization deleted successfully.", "success")
        except Exception as e:
            flash(request, f"Error deleting organization: {e}", "error")
        return redirect("/organizations")


# -----------------------------------------------------------------------------
# Permissions & RBAC Visual Editor
# -----------------------------------------------------------------------------


@get("/permissions")
async def permission_matrix(request: Request) -> Response:
    """Show the permission matrix view."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        roles = await service.list_roles()
        permissions = await service.get_all_permissions()

        # Build matrix data
        matrix: dict[str, set[str]] = {}
        for role in roles:
            matrix[role.name] = set(role.get_permissions_list())

        return render_template(
            request,
            "permissions/matrix.html",
            {
                "roles": roles,
                "permissions": permissions,
                "matrix": matrix,
            },
        )


@post("/permissions/toggle")
async def toggle_permission(request: Request) -> Response:
    """Toggle a permission for a role (HTMX endpoint)."""
    form_data = await request.form()
    role_name = form_data.get("role_name", "").strip()
    permission = form_data.get("permission", "").strip()
    enabled = form_data.get("enabled") == "true"

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            role = await service.get_role(role_name)
        except DoesNotExist:
            return _permission_cell_error("Role not found")
        if role.is_system:
            return _permission_cell_error("System role")

        await service.toggle_role_permission(role_name, permission, enabled=enabled)
        await session.commit()

    # Return the updated checkbox. Every interpolated value is escaped: role
    # and permission names come from the client.
    hx_vals = json.dumps({
        "role_name": role_name,
        "permission": permission,
        "enabled": "false" if enabled else "true",
    })
    checked = "checked" if enabled else ""
    return Response(
        content=f"""<input type="checkbox" {checked}
            class="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-600"
            hx-post="/permissions/toggle"
            hx-vals="{escape(hx_vals)}"
            hx-swap="outerHTML">""",
        status_code=200,
        media_type="text/html",
    )


def _permission_cell_error(message: str) -> Response:
    """Inline error shown in place of a permission checkbox.

    Status 200 so HTMX swaps it in (it ignores 4xx responses by default).
    """
    return Response(
        content=f'<span class="text-red-500 text-xs">{escape(message)}</span>',
        status_code=200,
        media_type="text/html",
    )


@get("/permissions/role-builder", sync_to_thread=False)
def role_builder_form(request: Request) -> Response:
    """Show the role builder wizard."""
    return render_template(request, "permissions/role_builder.html", {})


@post("/permissions/role-builder")
async def create_custom_role(request: Request) -> Response:
    """Create a custom role from the role builder."""
    form_data = await request.form()
    name = form_data.get("name", "").strip()
    description = form_data.get("description", "").strip()
    permissions_str = form_data.get("permissions", "")

    if not name:
        flash(request, "Role name is required.", "error")
        return redirect("/permissions/role-builder")

    # Parse permissions from form (comma-separated or multiple values)
    permissions: list[str]
    if isinstance(permissions_str, str):
        permissions = [p.strip() for p in permissions_str.split(",") if p.strip()]
    else:
        permissions = [str(p).strip() for p in permissions_str if str(p).strip()]

    if not permissions:
        flash(request, "At least one permission is required.", "error")
        return redirect("/permissions/role-builder")

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.create_role(name, permissions, description)
            await session.commit()
            flash(request, f"Role '{name}' created successfully.", "success")
            return redirect("/roles")
        except Exception as e:
            flash(request, f"Error creating role: {e}", "error")
            return redirect("/permissions/role-builder")


@get("/permissions/access-analyzer")
async def access_analyzer(request: Request) -> Response:
    """Show the access analyzer page."""
    query_type = request.query_params.get("type")
    query_value = request.query_params.get("value", "").strip()

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        all_permissions = await service.get_all_permissions()
        all_users = await service.list_subjects(limit=100)

        results = None
        if query_type and query_value:
            if query_type == "permission":
                # Who has access to this permission?
                results = await service.get_subjects_with_permission(query_value)
            elif query_type == "user":
                # What can this user do?
                results = await service.get_effective_permissions(query_value)

        return render_template(
            request,
            "permissions/access_analyzer.html",
            {
                "permissions": all_permissions,
                "users": all_users,
                "query_type": query_type,
                "query_value": query_value,
                "results": results,
            },
        )


# -----------------------------------------------------------------------------
# Audit Logs
# -----------------------------------------------------------------------------


@get("/audit")
async def list_audit_logs(request: Request) -> Response:
    """List audit logs with filters."""
    # Parse query parameters
    search = request.query_params.get("search")
    event_type = request.query_params.get("event_type")
    action = request.query_params.get("action")
    outcome = request.query_params.get("outcome")
    page = int(request.query_params.get("page", "1"))
    per_page = 50

    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        logs = await service.list_audit_logs(
            search=search,
            event_type=event_type,
            action=action,
            outcome=outcome,
            offset=(page - 1) * per_page,
            limit=per_page,
        )
        total = await service.count_audit_logs(
            event_type=event_type, action=action, outcome=outcome
        )

        # Get unique values for filters
        all_logs = await service.list_audit_logs(limit=500)
        event_types = sorted({log.event_type for log in all_logs if log.event_type})
        actions = sorted({log.action for log in all_logs if log.action})

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
async def audit_log_tail(request: Request) -> Response:
    """HTMX live-tail endpoint for the audit log table.

    Returns just the audit log table partial. The audit list page polls
    this every 10s when viewing page 1 without filters. Always returns
    the most recent N events; ignores filter params (the live tail is
    a fixed view).
    """
    per_page = 50
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
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
async def audit_log_detail(request: Request, entry_id: FromPath[str]) -> Response:
    """View audit log entry details."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
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


# -----------------------------------------------------------------------------
# Security Dashboard
# -----------------------------------------------------------------------------


@get("/security")
async def security_dashboard(request: Request) -> Response:
    """Security dashboard with metrics and insights."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)

        # Get audit stats
        stats = await service.get_audit_stats(days=7)
        login_activity = await service.get_login_activity(days=7)

        # Get MFA adoption
        subjects = await service.list_subjects(limit=1000)
        total_users = len(subjects)
        mfa_enabled_users = sum(1 for s in subjects if s.totp_enabled)
        mfa_adoption = (mfa_enabled_users / total_users * 100) if total_users > 0 else 0

        # Get active sessions
        sessions = await service.list_sessions(active_only=True)
        active_session_count = len(sessions)

        # Recent security events
        recent_events = await service.list_audit_logs(limit=10)

        return render_template(
            request,
            "security/dashboard.html",
            {
                "stats": stats,
                "login_activity": login_activity,
                "total_users": total_users,
                "mfa_enabled_users": mfa_enabled_users,
                "mfa_adoption": mfa_adoption,
                "active_session_count": active_session_count,
                "recent_events": recent_events,
            },
        )


@get("/security/stats")
async def security_stats(request: Request) -> Response:
    """HTMX live-polling endpoint for the security dashboard counters.

    Returns just the security stats partial. The security dashboard
    polls this every 15s.
    """
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        stats = await service.get_audit_stats(days=7)
        subjects = await service.list_subjects(limit=1000)
        total_users = len(subjects)
        mfa_enabled_users = sum(1 for s in subjects if s.totp_enabled)
        mfa_adoption = (mfa_enabled_users / total_users * 100) if total_users > 0 else 0
        sessions = await service.list_sessions(active_only=True)
        active_session_count = len(sessions)

    templates: Environment = request.app.state.templates
    content = templates.get_template("security/_stats.html").render(
        stats=stats,
        total_users=total_users,
        mfa_enabled_users=mfa_enabled_users,
        mfa_adoption=mfa_adoption,
        active_session_count=active_session_count,
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


# -----------------------------------------------------------------------------
# Settings (placeholder)
# -----------------------------------------------------------------------------


@get("/settings", sync_to_thread=False)
def settings(request: Request) -> Response:
    """Settings hub page."""
    return render_template(
        request,
        "settings/index.html",
        {},
    )


@get("/settings/identity-providers", sync_to_thread=False)
def identity_providers(request: Request) -> Response:
    """Identity providers configuration page."""
    return render_template(
        request,
        "settings/identity_providers.html",
        {},
    )


@get("/settings/social-providers", sync_to_thread=False)
def social_providers(request: Request) -> Response:
    """Social login providers configuration page."""
    return render_template(
        request,
        "settings/social_providers.html",
        {},
    )


@get("/settings/api-keys", sync_to_thread=False)
def api_keys(request: Request) -> Response:
    """API keys management page."""
    return render_template(
        request,
        "settings/api_keys.html",
        {},
    )


@get("/settings/webhooks", sync_to_thread=False)
def webhooks(request: Request) -> Response:
    """Webhooks configuration page."""
    return render_template(
        request,
        "settings/webhooks.html",
        {},
    )


@get("/settings/oauth-clients", sync_to_thread=False)
def oauth_clients(request: Request) -> Response:
    """OAuth clients management page."""
    return render_template(
        request,
        "settings/oauth_clients.html",
        {},
    )


@get("/settings/branding", sync_to_thread=False)
def branding(request: Request) -> Response:
    """Branding settings page."""
    return render_template(
        request,
        "settings/branding.html",
        {},
    )


@get("/settings/email-templates", sync_to_thread=False)
def email_templates(request: Request) -> Response:
    """Email templates configuration page."""
    return render_template(
        request,
        "settings/email_templates.html",
        {},
    )


@get("/settings/health", sync_to_thread=False)
def system_health(request: Request) -> Response:
    """System health status page."""
    return render_template(
        request,
        "settings/health.html",
        {},
    )


# -----------------------------------------------------------------------------
# App Factory
# -----------------------------------------------------------------------------


# Every admin console route, shared with `neozen serve`.
ROUTE_HANDLERS: list[Any] = [
    # Authentication
    login_page,
    login,
    logout,
    # Dashboard
    dashboard,
    dashboard_stats,
    # Users
    list_users,
    create_user_form,
    create_user,
    import_users_form,
    import_users,
    export_users,
    user_detail,
    activate_user,
    deactivate_user,
    delete_user,
    revoke_user_sessions,
    add_user_role,
    remove_user_role,
    impersonate_user,
    end_impersonation,
    list_subjects,  # Legacy redirect
    # Roles
    list_roles,
    create_role_form,
    create_role,
    role_detail,
    delete_role,
    # Sessions
    list_sessions,
    revoke_session,
    # Groups
    list_groups,
    create_group_form,
    create_group,
    group_detail,
    add_group_member,
    remove_group_member,
    add_group_role,
    remove_group_role,
    delete_group,
    # Organizations
    list_organizations,
    create_organization_form,
    create_organization,
    organization_detail,
    update_organization,
    delete_organization,
    # Permissions & RBAC Visual Editor
    permission_matrix,
    toggle_permission,
    role_builder_form,
    create_custom_role,
    access_analyzer,
    # Audit
    list_audit_logs,
    audit_log_tail,
    audit_log_detail,
    # Security
    security_dashboard,
    security_stats,
    security_policies,
    # Settings
    settings,
    identity_providers,
    social_providers,
    api_keys,
    webhooks,
    oauth_clients,
    branding,
    email_templates,
    system_health,
]

# Authentication setup, shared with `neozen serve`. The session middleware
# must come before AUTH_MIDDLEWARE.
AUTH_MIDDLEWARE = DefineMiddleware(AdminAuthMiddleware)
EXCEPTION_HANDLERS: dict[Any, Any] = {NotAuthorizedException: redirect_to_login_handler}


def session_config(config: AdminConfig) -> RotatingSessionConfig:
    """Session settings for the admin console (login state and flash messages)."""
    return RotatingSessionConfig(
        key=config.cookie_name,
        max_age=86400,
        secure=config.cookie_secure,
    )


def create_admin_app(config: AdminConfig | None = None) -> Litestar:
    """Create the admin Litestar application.

    Args:
        config: Admin configuration. If not provided, uses environment variables.

    Returns:
        Configured Litestar application
    """
    if config is None:
        config = AdminConfig(
            db_url=os.environ.get(
                "NEOZEN_DATABASE_URL", "sqlite+aiosqlite:///data/neozen.db"
            ),
            secret_key=os.environ.get(
                "NEOZEN_SECRET_KEY", "admin-secret-key-change-me"
            ),
        )

    # Create async engine
    engine = create_async_engine(config.db_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def on_startup() -> None:
        """Initialize database on startup."""
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Ensure built-in roles exist
        async with session_factory() as session:
            service = AdminService(session)
            await service.ensure_builtin_roles()
            await session.commit()

    def on_app_init(app_config: Any) -> Any:
        """Initialize app state."""
        return app_config

    sessions = session_config(config)

    app = Litestar(
        route_handlers=ROUTE_HANDLERS,
        middleware=[sessions.middleware, AUTH_MIDDLEWARE],
        exception_handlers=EXCEPTION_HANDLERS,
        on_startup=[on_startup],
        state=State({
            "config": config,
            "session_factory": session_factory,
            "templates": get_templates(config),
        }),
    )

    return app


__all__ = [
    "AUTH_MIDDLEWARE",
    "EXCEPTION_HANDLERS",
    "ROUTE_HANDLERS",
    "AdminConfig",
    "create_admin_app",
    "session_config",
]
