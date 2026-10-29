"""Admin console group management."""

from __future__ import annotations

from litestar import Request, Response, get, post
from litestar.params import FromPath

from neozen.admin.auth import (
    get_current_admin,
)
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
# Group Management
# -----------------------------------------------------------------------------


@get("/groups")
async def list_groups(request: Request, service: AdminService) -> Response:
    """List all groups."""
    search = request.query_params.get("search")
    groups = await service.list_groups(search=search)
    return render_template(
        request, "groups/list.html", {"groups": groups, "search": search}
    )


@get("/groups/create", sync_to_thread=False)
def create_group_form(request: Request) -> Response:
    """Show create group form."""
    return render_template(request, "groups/create.html", {})


@post("/groups/create")
async def create_group(request: Request, service: AdminService) -> Response:
    """Create a new group."""
    form_data = await request.form()
    name = form_data.get("name", "").strip()
    description = form_data.get("description", "").strip()

    if not name:
        flash(request, "Group name is required.", "error")
        return redirect("/groups/create")

    try:
        group = await service.create_group(name=name, description=description)
        await commit_audited(request, service)
        flash(request, f"Group '{name}' created successfully.", "success")
        return redirect(f"/groups/{group.id}")
    except ADMIN_ERRORS as e:
        flash(request, f"Error creating group: {describe_error(e)}", "error")
        return redirect("/groups/create")


@get("/groups/{group_id:str}")
async def group_detail(
    request: Request, service: AdminService, group_id: FromPath[str]
) -> Response:
    """View group details."""
    tab = request.query_params.get("tab", "members")
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
    except ADMIN_ERRORS:
        flash(request, f"Group not found: {group_id}", "error")
        return redirect("/groups")


@post("/groups/{group_id:str}/members/add")
async def add_group_member(
    request: Request, service: AdminService, group_id: FromPath[str]
) -> Response:
    """Add a member to a group."""
    form_data = await request.form()
    subject_id = form_data.get("subject_id", "").strip()
    role = form_data.get("role", "member").strip()

    if not subject_id:
        flash(request, "User is required.", "error")
        return redirect(f"/groups/{group_id}?tab=members")

    admin = get_current_admin(request)
    try:
        await service.add_group_member(
            group_id, subject_id, role=role, added_by=admin.id if admin else None
        )
        await commit_audited(request, service)
        flash(request, "Member added successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error adding member: {describe_error(e)}", "error")
    return redirect(f"/groups/{group_id}?tab=members")


@post("/groups/{group_id:str}/members/{subject_id:str}/remove")
async def remove_group_member(
    request: Request,
    service: AdminService,
    group_id: FromPath[str],
    subject_id: FromPath[str],
) -> Response:
    """Remove a member from a group."""
    try:
        await service.remove_group_member(group_id, subject_id)
        await commit_audited(request, service)
        flash(request, "Member removed successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error removing member: {describe_error(e)}", "error")
    return redirect(f"/groups/{group_id}?tab=members")


@post("/groups/{group_id:str}/roles/add")
async def add_group_role(
    request: Request, service: AdminService, group_id: FromPath[str]
) -> Response:
    """Add a role to a group."""
    form_data = await request.form()
    role_name = form_data.get("role_name", "").strip()

    if not role_name:
        flash(request, "Role is required.", "error")
        return redirect(f"/groups/{group_id}?tab=roles")

    admin = get_current_admin(request)
    try:
        await service.assign_role_to_group(
            group_id, role_name, granted_by=admin.id if admin else None
        )
        await commit_audited(request, service)
        flash(request, f"Role '{role_name}' assigned to group.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error assigning role: {describe_error(e)}", "error")
    return redirect(f"/groups/{group_id}?tab=roles")


@post("/groups/{group_id:str}/roles/{role_name:str}/remove")
async def remove_group_role(
    request: Request,
    service: AdminService,
    group_id: FromPath[str],
    role_name: FromPath[str],
) -> Response:
    """Remove a role from a group."""
    try:
        await service.remove_role_from_group(group_id, role_name)
        await commit_audited(request, service)
        flash(request, f"Role '{role_name}' removed from group.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error removing role: {describe_error(e)}", "error")
    return redirect(f"/groups/{group_id}?tab=roles")


@post("/groups/{group_id:str}/delete")
async def delete_group(
    request: Request, service: AdminService, group_id: FromPath[str]
) -> Response:
    """Delete a group."""
    try:
        await service.delete_group(group_id)
        await commit_audited(request, service)
        flash(request, "Group deleted successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error deleting group: {describe_error(e)}", "error")
    return redirect("/groups")
