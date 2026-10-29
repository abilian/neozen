"""Admin console permission tools: matrix, role builder, access analyzer."""

from __future__ import annotations

import json

from litestar import Request, Response, get, post
from markupsafe import escape

from neozen.admin.services import AdminService
from neozen.admin.web import (
    ADMIN_ERRORS,
    describe_error,
    flash,
    redirect,
    render_template,
)
from neozen.storage import DoesNotExist

# -----------------------------------------------------------------------------
# Permissions & RBAC Visual Editor
# -----------------------------------------------------------------------------


@get("/permissions")
async def permission_matrix(request: Request, service: AdminService) -> Response:
    """Show the permission matrix view."""
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
async def toggle_permission(request: Request, service: AdminService) -> Response:
    """Toggle a permission for a role (HTMX endpoint)."""
    form_data = await request.form()
    role_name = form_data.get("role_name", "").strip()
    permission = form_data.get("permission", "").strip()
    enabled = form_data.get("enabled") == "true"

    try:
        role = await service.get_role(role_name)
    except DoesNotExist:
        return _permission_cell_error("Role not found")
    if role.is_system:
        return _permission_cell_error("System role")

    await service.toggle_role_permission(role_name, permission, enabled=enabled)
    await service.session.commit()

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
async def create_custom_role(request: Request, service: AdminService) -> Response:
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

    try:
        await service.create_role(name, permissions, description)
        await service.session.commit()
        flash(request, f"Role '{name}' created successfully.", "success")
        return redirect("/roles")
    except ADMIN_ERRORS as e:
        flash(request, f"Error creating role: {describe_error(e)}", "error")
        return redirect("/permissions/role-builder")


@get("/permissions/access-analyzer")
async def access_analyzer(request: Request, service: AdminService) -> Response:
    """Show the access analyzer page."""
    query_type = request.query_params.get("type")
    query_value = request.query_params.get("value", "").strip()

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
