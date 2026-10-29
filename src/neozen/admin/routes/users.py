"""Admin console user management."""

from __future__ import annotations

from litestar import Request, Response, get, post
from litestar.params import FromPath

from neozen.admin.auth import (
    get_current_admin,
    get_impersonation,
    start_impersonation,
    stop_impersonation,
)
from neozen.admin.services import AdminService, UserListFilters
from neozen.admin.web import (
    ADMIN_ERRORS,
    Page,
    PerPage,
    describe_error,
    flash,
    redirect,
    render_template,
)
from neozen.core.audit.types import AuditActions
from neozen.ext.litestar.rate_limit import get_client_ip

# -----------------------------------------------------------------------------
# User Management (formerly Subject Management)
# -----------------------------------------------------------------------------


@get("/users")
async def list_users(
    request: Request, service: AdminService, page: Page = 1, per_page: PerPage = 50
) -> Response:
    """List all users with search, filters, and pagination."""
    # Parse query parameters
    search = request.query_params.get("search")
    status = request.query_params.get("status")
    mfa = request.query_params.get("mfa")
    verified = request.query_params.get("verified")
    sort_by = request.query_params.get("sort", "created_at")
    sort_order = request.query_params.get("order", "desc")

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
async def user_detail(
    request: Request, service: AdminService, user_id: FromPath[str]
) -> Response:
    """View user details with tabs."""
    tab = request.query_params.get("tab", "profile")
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
    except ADMIN_ERRORS:
        flash(request, f"User not found: {user_id}", "error")
        return redirect("/users")


@post("/users/{user_id:str}/activate")
async def activate_user(
    request: Request, service: AdminService, user_id: FromPath[str]
) -> Response:
    """Activate a user."""
    try:
        await service.activate_subject(user_id)
        await service.session.commit()
        flash(request, "User activated successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error activating user: {describe_error(e)}", "error")
    return redirect(f"/users/{user_id}")


@post("/users/{user_id:str}/deactivate")
async def deactivate_user(
    request: Request, service: AdminService, user_id: FromPath[str]
) -> Response:
    """Deactivate a user."""
    try:
        await service.deactivate_subject(user_id)
        await service.session.commit()
        flash(request, "User deactivated successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error deactivating user: {describe_error(e)}", "error")
    return redirect(f"/users/{user_id}")


@get("/users/create", sync_to_thread=False)
def create_user_form(request: Request) -> Response:
    """Show create user form."""
    return render_template(request, "users/create.html", {})


@post("/users/create")
async def create_user(request: Request, service: AdminService) -> Response:
    """Create a new user."""
    form_data = await request.form()
    email = form_data.get("email", "").strip()
    username = form_data.get("username", "").strip() or None

    if not email:
        flash(request, "Email is required.", "error")
        return redirect("/users/create")

    try:
        user = await service.create_subject(
            email=email,
            username=username,
            is_active=form_data.get("is_active") == "on",
            is_verified=form_data.get("is_verified") == "on",
        )
        await service.session.commit()
        flash(request, f"User '{email}' created successfully.", "success")
        return redirect(f"/users/{user.id}")
    except ADMIN_ERRORS as e:
        flash(request, f"Error creating user: {describe_error(e)}", "error")
        return redirect("/users/create")


@post("/users/{user_id:str}/delete")
async def delete_user(
    request: Request, service: AdminService, user_id: FromPath[str]
) -> Response:
    """Delete a user."""
    try:
        await service.delete_subject(user_id)
        await service.session.commit()
        flash(request, "User deleted successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error deleting user: {describe_error(e)}", "error")
    return redirect("/users")


@post("/users/{user_id:str}/revoke-sessions")
async def revoke_user_sessions(
    request: Request, service: AdminService, user_id: FromPath[str]
) -> Response:
    """Revoke all sessions for a user."""
    try:
        count = await service.revoke_all_subject_sessions(user_id)
        await service.session.commit()
        flash(request, f"Revoked {count} session(s) successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error revoking sessions: {describe_error(e)}", "error")
    return redirect(f"/users/{user_id}?tab=sessions")


@post("/users/{user_id:str}/roles/add")
async def add_user_role(
    request: Request, service: AdminService, user_id: FromPath[str]
) -> Response:
    """Add a role to a user."""
    form_data = await request.form()
    role_name = form_data.get("role_name", "").strip()

    if not role_name:
        flash(request, "Role name is required.", "error")
        return redirect(f"/users/{user_id}?tab=roles")

    admin = get_current_admin(request)
    try:
        await service.assign_role_to_subject(
            user_id, role_name, granted_by=admin.id if admin else None
        )
        await service.session.commit()
        flash(request, f"Role '{role_name}' assigned successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error assigning role: {describe_error(e)}", "error")
    return redirect(f"/users/{user_id}?tab=roles")


@post("/users/{user_id:str}/roles/{role_name:str}/remove")
async def remove_user_role(
    request: Request,
    service: AdminService,
    user_id: FromPath[str],
    role_name: FromPath[str],
) -> Response:
    """Remove a role from a user."""
    try:
        await service.remove_role_from_subject(user_id, role_name)
        await service.session.commit()
        flash(request, f"Role '{role_name}' removed successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error removing role: {describe_error(e)}", "error")
    return redirect(f"/users/{user_id}?tab=roles")


@get("/users/import", sync_to_thread=False)
def import_users_form(request: Request) -> Response:
    """Show bulk import form."""
    return render_template(request, "users/import.html", {"result": None})


@post("/users/import")
async def import_users(request: Request, service: AdminService) -> Response:
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
    result = await import_subjects_from_csv(
        service,
        content,
        dry_run=dry_run,
        update_existing=update_existing,
    )
    if not dry_run:
        await service.session.commit()

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
async def export_users(request: Request, service: AdminService) -> Response:
    """Export all subjects as CSV."""
    from neozen.admin.bulk import export_subjects_to_csv  # noqa: PLC0415

    csv_text = await export_subjects_to_csv(service)

    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="neozen-users.csv"',
        },
    )


@post("/users/{user_id:str}/impersonate")
async def impersonate_user(
    request: Request, service: AdminService, user_id: FromPath[str]
) -> Response:
    """Start impersonating a user."""
    admin = get_current_admin(request)
    if not admin or not admin.is_superadmin:
        flash(request, "Only superadmins can impersonate users.", "error")
        return redirect(f"/users/{user_id}")

    try:
        user = await service.get_subject(user_id)
        await service.record_admin_action(
            action=AuditActions.ADMIN_IMPERSONATE,
            actor_id=admin.id,
            subject_id=user.id,
            ip_address=get_client_ip(request.scope),
        )
        await service.session.commit()
        start_impersonation(request, user.id, user.email, user.username)
        flash(
            request,
            f"Now impersonating {user.email}. Click 'Stop Impersonation' to return.",
            "success",
        )
    except ADMIN_ERRORS as e:
        flash(request, f"Error starting impersonation: {describe_error(e)}", "error")
    return redirect(f"/users/{user_id}")


@post("/stop-impersonation")
async def end_impersonation(request: Request, service: AdminService) -> Response:
    """Stop impersonating a user."""
    impersonation = get_impersonation(request)
    admin = get_current_admin(request)
    if impersonation and admin:
        await service.record_admin_action(
            action=AuditActions.ADMIN_IMPERSONATE_END,
            actor_id=admin.id,
            subject_id=impersonation["user_id"],
            ip_address=get_client_ip(request.scope),
        )
        await service.session.commit()
    stop_impersonation(request)
    flash(request, "Stopped impersonation.", "success")
    return redirect("/")


# Legacy routes for backwards compatibility
@get("/subjects", sync_to_thread=False)
def list_subjects(request: Request) -> Response:
    """Redirect to users list."""
    return redirect("/users")
