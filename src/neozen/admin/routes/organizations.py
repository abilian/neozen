"""Admin console organization management."""

from __future__ import annotations

from litestar import Request, Response, get, post
from litestar.params import FromPath

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
# Organization Management
# -----------------------------------------------------------------------------


@get("/organizations")
async def list_organizations(request: Request, service: AdminService) -> Response:
    """List all organizations."""
    search = request.query_params.get("search")
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
async def create_organization(request: Request, service: AdminService) -> Response:
    """Create a new organization."""
    form_data = await request.form()
    name = form_data.get("name", "").strip()
    slug = form_data.get("slug", "").strip()
    domain = form_data.get("domain", "").strip() or None
    plan = form_data.get("plan", "free").strip()

    if not name or not slug:
        flash(request, "Name and slug are required.", "error")
        return redirect("/organizations/create")

    try:
        org = await service.create_organization(
            name=name, slug=slug, domain=domain, plan=plan
        )
        await commit_audited(request, service)
        flash(request, f"Organization '{name}' created successfully.", "success")
        return redirect(f"/organizations/{org.id}")
    except ADMIN_ERRORS as e:
        flash(request, f"Error creating organization: {describe_error(e)}", "error")
        return redirect("/organizations/create")


@get("/organizations/{org_id:str}")
async def organization_detail(
    request: Request, service: AdminService, org_id: FromPath[str]
) -> Response:
    """View organization details."""
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
    except ADMIN_ERRORS:
        flash(request, f"Organization not found: {org_id}", "error")
        return redirect("/organizations")


@post("/organizations/{org_id:str}/update")
async def update_organization(
    request: Request, service: AdminService, org_id: FromPath[str]
) -> Response:
    """Update an organization."""
    form_data = await request.form()
    name = form_data.get("name", "").strip() or None
    domain = form_data.get("domain", "").strip() or None
    plan = form_data.get("plan", "").strip() or None
    is_active = form_data.get("is_active") == "on"

    try:
        await service.update_organization(
            org_id, name=name, domain=domain, plan=plan, is_active=is_active
        )
        await commit_audited(request, service)
        flash(request, "Organization updated successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error updating organization: {describe_error(e)}", "error")
    return redirect(f"/organizations/{org_id}")


@post("/organizations/{org_id:str}/delete")
async def delete_organization(
    request: Request, service: AdminService, org_id: FromPath[str]
) -> Response:
    """Delete an organization."""
    try:
        await service.delete_organization(org_id)
        await commit_audited(request, service)
        flash(request, "Organization deleted successfully.", "success")
    except ADMIN_ERRORS as e:
        flash(request, f"Error deleting organization: {describe_error(e)}", "error")
    return redirect("/organizations")
