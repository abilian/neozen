"""Helpers shared by the admin console's routes."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Annotated, Any

from advanced_alchemy.exceptions import IntegrityError as RepositoryIntegrityError
from jinja2 import Environment, FileSystemLoader
from litestar import Request, Response
from litestar.params import Parameter
from litestar.status_codes import HTTP_303_SEE_OTHER
from litestar.template.base import csrf_token
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker

from neozen.admin.auth import (
    get_current_admin,
    get_impersonation,
)
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService
from neozen.core.exceptions import NeoZenException
from neozen.storage import DoesNotExist

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
    ctx["csrf_token"] = csrf_token({"request": request})
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


# Failures an admin action can expect; anything else is a bug and propagates.
# Duplicates arrive as Advanced Alchemy's error from repositories, and as
# SQLAlchemy's from a commit.
_CONFLICT_ERRORS = (RepositoryIntegrityError, IntegrityError)
ADMIN_ERRORS = (DoesNotExist, *_CONFLICT_ERRORS, NeoZenException, ValueError)


def describe_error(error: Exception) -> str:
    """A message for the admin, without database details."""
    if isinstance(error, DoesNotExist):
        return "not found."
    if isinstance(error, _CONFLICT_ERRORS):
        return "it conflicts with an existing record (duplicate name or email?)."
    return str(error)  # NeoZen and validation errors are written for users


# Pagination query parameters: Litestar answers 400 to anything else.
Page = Annotated[int, Parameter(ge=1)]
PerPage = Annotated[int, Parameter(ge=1, le=200)]
