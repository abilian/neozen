"""Admin console role management."""

from __future__ import annotations

from litestar import Request, Response, get, post
from litestar.params import FromPath

from neozen.admin.auth import superadmin_only
from neozen.admin.services import AdminService
from neozen.admin.web import (
    ADMIN_ERRORS,
    commit_audited,
    describe_error,
    flash,
    redirect,
    render_template,
)

# -----------------------------------------------------------------------------
# Role Management
# -----------------------------------------------------------------------------


@get("/roles")
async def list_roles(request: Request, service: AdminService) -> Response:
    """List all roles."""
    roles = await service.list_roles()
    return render_template(request, "roles/list.html", {"roles": roles})


@get("/roles/create", sync_to_thread=False)
def create_role_form(request: Request) -> Response:
    """Show create role form."""
    return render_template(request, "roles/create.html", {})


@post("/roles/create", guards=[superadmin_only])
async def create_role(request: Request, service: AdminService) -> Response:
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

    try:
        await service.create_role(name, permissions, description)
        await commit_audited(request, service)
        flash(request, f"Role '{name}' created successfully.", "success")
        return redirect("/roles")
    except ADMIN_ERRORS as e:
        flash(request, f"Error creating role: {describe_error(e)}", "error")
        return redirect("/roles/create")


@get("/roles/{role_name:str}")
async def role_detail(
    request: Request, service: AdminService, role_name: FromPath[str]
) -> Response:
    """View role details."""
    try:
        role = await service.get_role(role_name)
    except ADMIN_ERRORS:
        flash(request, f"Role not found: {role_name}", "error")
        return redirect("/roles")

    assignments_with_subjects = await service.get_role_assignments_with_subjects(role)
    return render_template(
        request,
        "roles/detail.html",
        {
            "role": role,
            "assignments": assignments_with_subjects,
        },
    )


@post("/roles/{role_name:str}/delete", guards=[superadmin_only])
async def delete_role(
    request: Request, service: AdminService, role_name: FromPath[str]
) -> Response:
    """Delete a role."""
    try:
        await service.delete_role(role_name)
        await commit_audited(request, service)
        flash(request, f"Role '{role_name}' deleted successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error deleting role: {describe_error(e)}", "error")
    return redirect("/roles")
