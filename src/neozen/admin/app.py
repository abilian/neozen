"""Admin UI Litestar application."""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from litestar import Litestar, Request, Response, get, post
from litestar.datastructures import State
from litestar.middleware.session.server_side import ServerSideSessionConfig
from litestar.status_codes import HTTP_303_SEE_OTHER
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.models import RoleAssignment, Session, Subject

# Template directory
TEMPLATES_DIR = Path(__file__).parent / "templates"


def get_templates(config: AdminConfig) -> Environment:
    """Create Jinja2 environment."""
    templates_dir = config.templates_dir or TEMPLATES_DIR
    return Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)


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
# Dashboard
# -----------------------------------------------------------------------------


@get("/")
async def dashboard(request: Request) -> Response:
    """Admin dashboard with statistics."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        stats = await service.get_dashboard_stats()
        return render_template(request, "dashboard.html", {"stats": stats})


# -----------------------------------------------------------------------------
# Subject Management
# -----------------------------------------------------------------------------


@get("/subjects")
async def list_subjects(request: Request) -> Response:
    """List all subjects."""
    search = request.query_params.get("search")
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        subjects = await service.list_subjects(search=search)
        return render_template(
            request, "subjects/list.html", {"subjects": subjects, "search": search}
        )


@get("/subjects/{subject_id:str}")
async def subject_detail(request: Request, subject_id: str) -> Response:
    """View subject details."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            subject = await service.get_subject(subject_id)
            roles = await service.get_subject_roles(subject_id)
            return render_template(
                request,
                "subjects/detail.html",
                {"subject": subject, "roles": roles},
            )
        except Exception:
            flash(request, f"Subject not found: {subject_id}", "error")
            return redirect("/subjects")


@post("/subjects/{subject_id:str}/activate")
async def activate_subject(request: Request, subject_id: str) -> Response:
    """Activate a subject."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.activate_subject(subject_id)
            await session.commit()
            flash(request, "Subject activated successfully.", "success")
        except Exception as e:
            flash(request, f"Error activating subject: {e}", "error")
        return redirect(f"/subjects/{subject_id}")


@post("/subjects/{subject_id:str}/deactivate")
async def deactivate_subject(request: Request, subject_id: str) -> Response:
    """Deactivate a subject."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            await service.deactivate_subject(subject_id)
            await session.commit()
            flash(request, "Subject deactivated successfully.", "success")
        except Exception as e:
            flash(request, f"Error deactivating subject: {e}", "error")
        return redirect(f"/subjects/{subject_id}")


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
async def role_detail(request: Request, role_name: str) -> Response:
    """View role details."""
    session_factory: async_sessionmaker = request.app.state.session_factory
    async with session_factory() as session:
        service = AdminService(session)
        try:
            role = await service.get_role(role_name)
            assignments = await service.get_role_assignments(role_name)

            # Get subject info for each assignment
            assignments_with_subjects: list[tuple[RoleAssignment, Subject | None]] = []
            for assignment in assignments:
                try:
                    subject = await service.get_subject(assignment.subject_id)
                    assignments_with_subjects.append((assignment, subject))
                except Exception:
                    assignments_with_subjects.append((assignment, None))

            return render_template(
                request,
                "roles/detail.html",
                {
                    "role": role,
                    "assignments": assignments_with_subjects,
                },
            )
        except Exception:
            flash(request, f"Role not found: {role_name}", "error")
            return redirect("/roles")


@post("/roles/{role_name:str}/delete")
async def delete_role(request: Request, role_name: str) -> Response:
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
async def revoke_session(request: Request, token_hash: str) -> Response:
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
# App Factory
# -----------------------------------------------------------------------------


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

    # Session middleware for flash messages
    session_config = ServerSideSessionConfig(
        key="neozen_admin_session",
        max_age=86400,
    )

    app = Litestar(
        route_handlers=[
            dashboard,
            list_subjects,
            subject_detail,
            activate_subject,
            deactivate_subject,
            list_roles,
            create_role_form,
            create_role,
            role_detail,
            delete_role,
            list_sessions,
            revoke_session,
        ],
        middleware=[session_config.middleware],
        on_startup=[on_startup],
        state=State({
            "config": config,
            "session_factory": session_factory,
            "templates": get_templates(config),
        }),
    )

    return app


__all__ = ["create_admin_app", "AdminConfig"]
