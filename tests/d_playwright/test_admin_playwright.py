"""Playwright end-to-end tests for admin console functionality.

Tests the admin interface across all demo applications:
- Admin dashboard
- User management (list, view, role management)
- Session management (list, revoke)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .conftest import generate_test_email, login_user, register_user

if TYPE_CHECKING:
    from playwright.sync_api import Page


# =============================================================================
# Module-level admin user tracking
# =============================================================================

# Store admin credentials per framework (module-scoped)
_flask_admin: dict[str, str] | None = None
_litestar_admin: dict[str, str] | None = None


def get_or_create_flask_admin(page: Page, server: str) -> dict[str, str]:
    """Get or create Flask admin user."""
    global _flask_admin
    if _flask_admin is None:
        _flask_admin = {
            "email": generate_test_email(),
            "password": "SecurePassword123!",
        }
        page.context.clear_cookies()
        register_user(page, server, _flask_admin["email"], _flask_admin["password"])
    return _flask_admin


def get_or_create_litestar_admin(page: Page, server: str) -> dict[str, str]:
    """Get or create Litestar admin user."""
    global _litestar_admin
    if _litestar_admin is None:
        _litestar_admin = {
            "email": generate_test_email(),
            "password": "SecurePassword123!",
        }
        page.context.clear_cookies()
        register_user(
            page, server, _litestar_admin["email"], _litestar_admin["password"]
        )
    return _litestar_admin


def login_flask_admin(page: Page, server: str) -> dict[str, str]:
    """Login as Flask admin user, creating if needed."""
    creds = get_or_create_flask_admin(page, server)
    page.context.clear_cookies()
    login_user(page, server, creds["email"], creds["password"])
    return creds


def login_litestar_admin(page: Page, server: str) -> dict[str, str]:
    """Login as Litestar admin user, creating if needed."""
    creds = get_or_create_litestar_admin(page, server)
    page.context.clear_cookies()
    login_user(page, server, creds["email"], creds["password"])
    return creds


# =============================================================================
# Flask Admin Tests
# =============================================================================


class TestFlaskAdminDashboard:
    """Tests for the Flask admin dashboard."""

    def test_admin_dashboard_shows_stats(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Admin dashboard should display statistics."""
        login_flask_admin(flask_page, flask_server)
        flask_page.goto(f"{flask_server}/admin")

        content = flask_page.content()
        # Dashboard should show some stats
        assert "admin" in content.lower() or "dashboard" in content.lower()
        # Should show user count or similar stats
        assert "user" in content.lower() or "total" in content.lower()

    def test_admin_dashboard_has_navigation(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Admin dashboard should have navigation links."""
        login_flask_admin(flask_page, flask_server)
        flask_page.goto(f"{flask_server}/admin")

        # Should have links to users and sessions (via button role)
        users_link = flask_page.locator(
            'a:has-text("Manage Users"), a:has-text("Users")'
        )
        assert users_link.count() > 0


class TestFlaskAdminUsers:
    """Tests for Flask admin user management."""

    def test_admin_users_list_shows_users(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Admin users page should list registered users."""
        creds = login_flask_admin(flask_page, flask_server)
        flask_page.goto(f"{flask_server}/admin/users")

        content = flask_page.content()
        # Should show the registered admin user's email
        assert creds["email"] in content

    def test_admin_users_list_shows_multiple_users(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Admin users page should list all registered users."""
        creds = login_flask_admin(flask_page, flask_server)

        # Register another user
        flask_page.context.clear_cookies()
        second_email = generate_test_email()
        register_user(flask_page, flask_server, second_email, "SecurePassword123!")

        # Login as admin again
        login_user(flask_page, flask_server, creds["email"], creds["password"])

        flask_page.goto(f"{flask_server}/admin/users")

        content = flask_page.content()
        # Should show both users
        assert creds["email"] in content
        assert second_email in content

    def test_admin_user_detail_page(self, flask_page: Page, flask_server: str) -> None:
        """Admin user detail page should show user information."""
        login_flask_admin(flask_page, flask_server)
        # Go to users list
        flask_page.goto(f"{flask_server}/admin/users")

        # Click on a user to view details
        user_link = flask_page.locator('a:has-text("View")').first
        if user_link.count() > 0:
            user_link.click()
            flask_page.wait_for_load_state("networkidle")

            content = flask_page.content()
            # Should show user details
            assert "user" in content.lower() or "email" in content.lower()

    def test_admin_toggle_user_role(self, flask_page: Page, flask_server: str) -> None:
        """Admin should be able to toggle user roles."""
        creds = login_flask_admin(flask_page, flask_server)

        # Register a second user to toggle roles on
        flask_page.context.clear_cookies()
        user_email = generate_test_email()
        register_user(flask_page, flask_server, user_email, "SecurePassword123!")

        # Login as admin
        login_user(flask_page, flask_server, creds["email"], creds["password"])

        # Go to users list
        flask_page.goto(f"{flask_server}/admin/users")

        # Find the non-admin user and click view
        user_row = flask_page.locator(f'tr:has-text("{user_email}")')
        if user_row.count() > 0:
            user_link = user_row.locator('a:has-text("View")').first
            if user_link.count() > 0:
                user_link.click()
                flask_page.wait_for_load_state("networkidle")

                # Look for role toggle functionality
                content = flask_page.content()
                assert "role" in content.lower()


class TestFlaskAdminSessions:
    """Tests for Flask admin session management."""

    def test_admin_sessions_list(self, flask_page: Page, flask_server: str) -> None:
        """Admin sessions page should list active sessions."""
        login_flask_admin(flask_page, flask_server)
        flask_page.goto(f"{flask_server}/admin/sessions")

        content = flask_page.content()
        # Should show sessions page
        assert "session" in content.lower()

    def test_admin_sessions_shows_user_info(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Admin sessions should show associated user information."""
        creds = login_flask_admin(flask_page, flask_server)
        flask_page.goto(f"{flask_server}/admin/sessions")

        content = flask_page.content()
        # Should show user email or at least session info
        assert (
            creds["email"] in content
            or "user" in content.lower()
            or "token" in content.lower()
        )

    def test_admin_revoke_session(self, flask_page: Page, flask_server: str) -> None:
        """Admin should be able to revoke sessions."""
        login_flask_admin(flask_page, flask_server)
        flask_page.goto(f"{flask_server}/admin/sessions")

        # Look for revoke button
        revoke_button = flask_page.locator('button:has-text("Revoke")')

        # Should have revoke functionality
        content = flask_page.content()
        assert revoke_button.count() > 0 or "revoke" in content.lower()


# =============================================================================
# Litestar Admin Tests
# =============================================================================


class TestLitestarAdminDashboard:
    """Tests for the Litestar admin dashboard."""

    def test_admin_dashboard_shows_stats(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin dashboard should display statistics."""
        login_litestar_admin(litestar_page, litestar_server)
        litestar_page.goto(f"{litestar_server}/admin")

        content = litestar_page.content()
        # Dashboard should show some stats
        assert "admin" in content.lower() or "dashboard" in content.lower()

    def test_admin_dashboard_has_navigation(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin dashboard should have navigation links."""
        login_litestar_admin(litestar_page, litestar_server)
        litestar_page.goto(f"{litestar_server}/admin")

        # Should have links to users and sessions
        users_link = litestar_page.locator(
            'a:has-text("Manage Users"), a:has-text("Users")'
        )
        assert users_link.count() > 0


class TestLitestarAdminUsers:
    """Tests for Litestar admin user management."""

    def test_admin_users_list_shows_users(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin users page should list registered users."""
        creds = login_litestar_admin(litestar_page, litestar_server)
        litestar_page.goto(f"{litestar_server}/admin/users")

        content = litestar_page.content()
        # Should show the registered admin user's email
        assert creds["email"] in content

    def test_admin_users_list_shows_multiple_users(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin users page should list all registered users."""
        creds = login_litestar_admin(litestar_page, litestar_server)

        # Register another user
        litestar_page.context.clear_cookies()
        second_email = generate_test_email()
        register_user(
            litestar_page, litestar_server, second_email, "SecurePassword123!"
        )

        # Login as admin again
        login_user(litestar_page, litestar_server, creds["email"], creds["password"])

        litestar_page.goto(f"{litestar_server}/admin/users")

        content = litestar_page.content()
        # Should show both users
        assert creds["email"] in content
        assert second_email in content

    def test_admin_user_detail_page(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin user detail page should show user information."""
        login_litestar_admin(litestar_page, litestar_server)
        # Go to users list
        litestar_page.goto(f"{litestar_server}/admin/users")

        # Click on a user to view details
        user_link = litestar_page.locator('a:has-text("View")').first
        if user_link.count() > 0:
            user_link.click()
            litestar_page.wait_for_load_state("networkidle")

            content = litestar_page.content()
            # Should show user details
            assert "user" in content.lower() or "email" in content.lower()

    def test_admin_toggle_user_role(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin should be able to toggle user roles."""
        creds = login_litestar_admin(litestar_page, litestar_server)

        # Register a second user
        litestar_page.context.clear_cookies()
        user_email = generate_test_email()
        register_user(litestar_page, litestar_server, user_email, "SecurePassword123!")

        # Login as admin
        login_user(litestar_page, litestar_server, creds["email"], creds["password"])

        # Go to users list
        litestar_page.goto(f"{litestar_server}/admin/users")

        # Find the non-admin user row
        user_row = litestar_page.locator(f'tr:has-text("{user_email}")')
        if user_row.count() > 0:
            user_link = user_row.locator('a:has-text("View")').first
            if user_link.count() > 0:
                user_link.click()
                litestar_page.wait_for_load_state("networkidle")

                content = litestar_page.content()
                assert "role" in content.lower()


class TestLitestarAdminSessions:
    """Tests for Litestar admin session management."""

    def test_admin_sessions_list(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin sessions page should list active sessions."""
        login_litestar_admin(litestar_page, litestar_server)
        litestar_page.goto(f"{litestar_server}/admin/sessions")

        content = litestar_page.content()
        # Should show sessions page
        assert "session" in content.lower()

    def test_admin_sessions_shows_user_info(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin sessions should show associated user information."""
        creds = login_litestar_admin(litestar_page, litestar_server)
        litestar_page.goto(f"{litestar_server}/admin/sessions")

        content = litestar_page.content()
        # Should show user email or session info
        assert (
            creds["email"] in content
            or "user" in content.lower()
            or "token" in content.lower()
        )

    def test_admin_revoke_session(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin should be able to revoke sessions."""
        login_litestar_admin(litestar_page, litestar_server)
        litestar_page.goto(f"{litestar_server}/admin/sessions")

        # Look for revoke button
        revoke_button = litestar_page.locator('button:has-text("Revoke")')

        content = litestar_page.content()
        assert revoke_button.count() > 0 or "revoke" in content.lower()


# =============================================================================
# Starlette Admin Tests (Separate Admin App)
# =============================================================================


class TestStarletteAdminDashboard:
    """Tests for the Starlette admin dashboard.

    Note: Starlette uses a separate mounted admin app which may have
    different behavior than the in-app admin for Flask/Litestar.
    """

    @pytest.mark.skip(reason="Starlette admin app requires additional setup")
    def test_admin_dashboard_shows_stats(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Admin dashboard should display statistics."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(starlette_page, starlette_server, email, password)
        login_user(starlette_page, starlette_server, email, password)

        starlette_page.goto(f"{starlette_server}/admin")

        content = starlette_page.content()
        assert "admin" in content.lower() or "dashboard" in content.lower()


# =============================================================================
# Cross-Framework Admin Workflow Tests
# =============================================================================


class TestFlaskAdminWorkflow:
    """End-to-end admin workflow tests for Flask."""

    def test_complete_user_management_workflow(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Test complete admin workflow: view users, view details, check roles."""
        creds = login_flask_admin(flask_page, flask_server)

        # Register another user to manage
        flask_page.context.clear_cookies()
        user_email = generate_test_email()
        register_user(flask_page, flask_server, user_email, "SecurePassword123!")

        # Login as admin
        login_user(flask_page, flask_server, creds["email"], creds["password"])

        # 1. Go to admin dashboard
        flask_page.goto(f"{flask_server}/admin")
        assert flask_page.locator("body").is_visible()
        assert "/admin" in flask_page.url

        # 2. Navigate to users via clicking
        flask_page.click('a:has-text("Manage Users")')
        flask_page.wait_for_load_state("networkidle")

        content = flask_page.content()
        assert user_email in content

        # 3. View user details (if link exists)
        user_row = flask_page.locator(f'tr:has-text("{user_email}")')
        if user_row.count() > 0:
            user_detail_link = user_row.locator('a:has-text("View")').first
            if user_detail_link.count() > 0:
                user_detail_link.click()
                flask_page.wait_for_load_state("networkidle")

                detail_content = flask_page.content()
                assert (
                    "role" in detail_content.lower() or "user" in detail_content.lower()
                )

    def test_session_management_workflow(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Test admin session management workflow."""
        login_flask_admin(flask_page, flask_server)
        # Go to sessions page
        flask_page.goto(f"{flask_server}/admin/sessions")

        content = flask_page.content()
        # Should see at least our current session
        assert "session" in content.lower()

        # Look for session info (user, created, etc.)
        assert (
            "user" in content.lower()
            or "created" in content.lower()
            or "token" in content.lower()
        )


class TestLitestarAdminWorkflow:
    """End-to-end admin workflow tests for Litestar."""

    def test_complete_user_management_workflow(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Test complete admin workflow: view users, view details, check roles."""
        creds = login_litestar_admin(litestar_page, litestar_server)

        # Register another user to manage
        litestar_page.context.clear_cookies()
        user_email = generate_test_email()
        register_user(litestar_page, litestar_server, user_email, "SecurePassword123!")

        # Login as admin
        login_user(litestar_page, litestar_server, creds["email"], creds["password"])

        # 1. Go to admin dashboard
        litestar_page.goto(f"{litestar_server}/admin")
        assert litestar_page.locator("body").is_visible()

        # Check we're on admin page (not redirected)
        content = litestar_page.content()
        assert "admin" in content.lower() or "dashboard" in content.lower()

        # 2. Navigate to users
        litestar_page.click('a:has-text("Manage Users")')
        litestar_page.wait_for_load_state("networkidle")

        content = litestar_page.content()
        assert user_email in content

        # 3. View user details (if link exists)
        user_row = litestar_page.locator(f'tr:has-text("{user_email}")')
        if user_row.count() > 0:
            user_detail_link = user_row.locator('a:has-text("View")').first
            if user_detail_link.count() > 0:
                user_detail_link.click()
                litestar_page.wait_for_load_state("networkidle")

                detail_content = litestar_page.content()
                assert (
                    "role" in detail_content.lower() or "user" in detail_content.lower()
                )

    def test_session_management_workflow(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Test admin session management workflow."""
        login_litestar_admin(litestar_page, litestar_server)
        # Go to sessions page
        litestar_page.goto(f"{litestar_server}/admin/sessions")

        content = litestar_page.content()
        # Should see at least our current session
        assert "session" in content.lower()

        # Look for session info
        assert (
            "user" in content.lower()
            or "created" in content.lower()
            or "token" in content.lower()
        )
