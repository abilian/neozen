"""Admin console settings pages (placeholders)."""

from __future__ import annotations

from litestar import Request, Response, get

from neozen.admin.web import (
    render_template,
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
