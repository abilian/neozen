"""Playwright end-to-end tests for magic link authentication.

Tests the magic link flow across Flask and Litestar demos:
- Request magic link page loads
- Request sends email (via console sender)
- Clicking the magic link URL logs the user in
- Invalid/expired tokens are rejected
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .conftest import generate_test_email, register_user

if TYPE_CHECKING:
    from playwright.sync_api import Page


def _get_magic_link_url(page: Page, server: str) -> str | None:
    """Fetch the last magic link URL from the test API endpoint."""
    resp = page.request.get(f"{server}/api/test/last-magic-link")
    data = resp.json()
    return data.get("url")


# =============================================================================
# Flask Magic Link Tests
# =============================================================================


class TestFlaskMagicLinkPage:
    """Tests for the Flask magic link request page."""

    def test_magic_login_page_loads(self, flask_page: Page, flask_server: str) -> None:
        flask_page.goto(f"{flask_server}/magic-login")
        assert "Magic Link" in flask_page.content()
        assert flask_page.locator('input[name="email"]').count() > 0

    def test_login_page_has_magic_link_option(
        self, flask_page: Page, flask_server: str
    ) -> None:
        flask_page.goto(f"{flask_server}/login")
        link = flask_page.locator('a[href="/magic-login"]')
        assert link.count() > 0


class TestFlaskMagicLinkFlow:
    """Tests for the Flask magic link authentication flow."""

    def test_request_magic_link(self, flask_page: Page, flask_server: str) -> None:
        """Requesting a magic link should show success message."""
        email = generate_test_email()
        register_user(flask_page, flask_server, email, "SecurePassword123!")

        flask_page.goto(f"{flask_server}/magic-login")
        flask_page.fill('input[name="email"]', email)
        flask_page.click('button[type="submit"]')

        flask_page.wait_for_load_state("networkidle")
        content = flask_page.content()
        assert "magic link has been sent" in content.lower()

    def test_magic_link_logs_in(self, flask_page: Page, flask_server: str) -> None:
        """Clicking the magic link should log the user in."""
        email = generate_test_email()
        register_user(flask_page, flask_server, email, "SecurePassword123!")

        # Request magic link
        flask_page.goto(f"{flask_server}/magic-login")
        flask_page.fill('input[name="email"]', email)
        flask_page.click('button[type="submit"]')
        flask_page.wait_for_load_state("networkidle")

        # Get the magic link URL from the test API
        magic_url = _get_magic_link_url(flask_page, flask_server)
        assert magic_url is not None, "No magic link URL was generated"

        # Clear cookies so we're "logged out"
        flask_page.context.clear_cookies()

        # Click the magic link
        flask_page.goto(magic_url)
        flask_page.wait_for_load_state("networkidle")

        # Should be redirected to dashboard
        assert "/dashboard" in flask_page.url

    def test_magic_link_invalid_token(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Invalid token should show error."""
        flask_page.goto(f"{flask_server}/magic-login/verify?token=invalid_token_xyz")
        flask_page.wait_for_load_state("networkidle")

        # Should be redirected to login with error
        assert "/login" in flask_page.url

    def test_magic_link_token_single_use(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Token should only work once."""
        email = generate_test_email()
        register_user(flask_page, flask_server, email, "SecurePassword123!")

        # Request magic link
        flask_page.goto(f"{flask_server}/magic-login")
        flask_page.fill('input[name="email"]', email)
        flask_page.click('button[type="submit"]')
        flask_page.wait_for_load_state("networkidle")

        magic_url = _get_magic_link_url(flask_page, flask_server)
        assert magic_url is not None

        # First use: should log in
        flask_page.context.clear_cookies()
        flask_page.goto(magic_url)
        flask_page.wait_for_load_state("networkidle")
        assert "/dashboard" in flask_page.url

        # Second use: should fail
        flask_page.context.clear_cookies()
        flask_page.goto(magic_url)
        flask_page.wait_for_load_state("networkidle")
        assert "/login" in flask_page.url

    def test_nonexistent_email_no_error(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Requesting for nonexistent email should still show success."""
        flask_page.goto(f"{flask_server}/magic-login")
        flask_page.fill('input[name="email"]', "nobody@example.com")
        flask_page.click('button[type="submit"]')
        flask_page.wait_for_load_state("networkidle")

        content = flask_page.content()
        # Should NOT reveal that email doesn't exist
        assert "magic link has been sent" in content.lower()


# =============================================================================
# Litestar Magic Link Tests
# =============================================================================


class TestLitestarMagicLinkPage:
    """Tests for the Litestar magic link request page."""

    def test_magic_login_page_loads(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        litestar_page.goto(f"{litestar_server}/magic-login")
        assert "Magic Link" in litestar_page.content()
        assert litestar_page.locator('input[name="email"]').count() > 0

    def test_login_page_has_magic_link_option(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        litestar_page.goto(f"{litestar_server}/login")
        link = litestar_page.locator('a[href="/magic-login"]')
        assert link.count() > 0


class TestLitestarMagicLinkFlow:
    """Tests for the Litestar magic link authentication flow."""

    def test_request_magic_link(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Requesting a magic link should show success message."""
        email = generate_test_email()
        register_user(litestar_page, litestar_server, email, "SecurePassword123!")

        litestar_page.goto(f"{litestar_server}/magic-login")
        litestar_page.fill('input[name="email"]', email)
        litestar_page.click('button[type="submit"]')

        litestar_page.wait_for_load_state("networkidle")
        content = litestar_page.content()
        assert "magic link has been sent" in content.lower()

    def test_magic_link_logs_in(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Clicking the magic link should log the user in."""
        email = generate_test_email()
        register_user(litestar_page, litestar_server, email, "SecurePassword123!")

        # Request magic link
        litestar_page.goto(f"{litestar_server}/magic-login")
        litestar_page.fill('input[name="email"]', email)
        litestar_page.click('button[type="submit"]')
        litestar_page.wait_for_load_state("networkidle")

        # Get the magic link URL
        magic_url = _get_magic_link_url(litestar_page, litestar_server)
        assert magic_url is not None, "No magic link URL was generated"

        # Clear cookies
        litestar_page.context.clear_cookies()

        # Click the magic link
        litestar_page.goto(magic_url)
        litestar_page.wait_for_load_state("networkidle")

        # Should be redirected to dashboard
        assert "/dashboard" in litestar_page.url

    def test_magic_link_invalid_token(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Invalid token should show error."""
        litestar_page.goto(
            f"{litestar_server}/magic-login/verify?token=invalid_token_xyz"
        )
        litestar_page.wait_for_load_state("networkidle")

        # Should redirect to login
        assert "/login" in litestar_page.url

    def test_magic_link_token_single_use(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Token should only work once."""
        email = generate_test_email()
        register_user(litestar_page, litestar_server, email, "SecurePassword123!")

        litestar_page.goto(f"{litestar_server}/magic-login")
        litestar_page.fill('input[name="email"]', email)
        litestar_page.click('button[type="submit"]')
        litestar_page.wait_for_load_state("networkidle")

        magic_url = _get_magic_link_url(litestar_page, litestar_server)
        assert magic_url is not None

        # First use
        litestar_page.context.clear_cookies()
        litestar_page.goto(magic_url)
        litestar_page.wait_for_load_state("networkidle")
        assert "/dashboard" in litestar_page.url

        # Second use
        litestar_page.context.clear_cookies()
        litestar_page.goto(magic_url)
        litestar_page.wait_for_load_state("networkidle")
        assert "/login" in litestar_page.url

    def test_nonexistent_email_no_error(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Requesting for nonexistent email should still show success."""
        litestar_page.goto(f"{litestar_server}/magic-login")
        litestar_page.fill('input[name="email"]', "nobody@example.com")
        litestar_page.click('button[type="submit"]')
        litestar_page.wait_for_load_state("networkidle")

        content = litestar_page.content()
        assert "magic link has been sent" in content.lower()
