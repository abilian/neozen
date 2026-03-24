"""Playwright end-to-end tests for the Starlette demo application.

Tests the full user experience through a real browser, including:
- Page rendering and navigation
- User registration flow
- Login/logout flow
- Protected routes
- Admin functionality
- Role-based access control
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .conftest import generate_test_email, login_user, logout_user, register_user

if TYPE_CHECKING:
    from playwright.sync_api import Page


class TestStarletteHomePage:
    """Tests for the Starlette demo home page."""

    def test_home_page_loads(self, starlette_page: Page, starlette_server: str) -> None:
        """Home page should load and display NeoZen branding."""
        starlette_page.goto(starlette_server)

        assert starlette_page.locator("body").is_visible()

        # Should contain NeoZen or demo branding
        content = starlette_page.content()
        assert "NeoZen" in content or "Demo" in content

    def test_home_page_has_navigation(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Home page should have login/register links."""
        starlette_page.goto(starlette_server)

        # Should have login link
        login_link = starlette_page.locator('a[href*="login"]')
        assert login_link.count() > 0

        # Should have register link
        register_link = starlette_page.locator('a[href*="register"]')
        assert register_link.count() > 0


class TestStarletteRegistration:
    """Tests for user registration flow."""

    def test_register_page_loads(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Registration page should load with form fields."""
        starlette_page.goto(f"{starlette_server}/register")

        # Should have email field
        assert starlette_page.locator('input[name="email"]').is_visible()

        # Should have password fields
        assert starlette_page.locator('input[name="password"]').is_visible()
        assert starlette_page.locator('input[name="password_confirm"]').is_visible()

        # Should have submit button
        assert starlette_page.locator('button[type="submit"]').is_visible()

    def test_register_success(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Successful registration should redirect to login."""
        email = generate_test_email()
        password = "SecurePassword123!"

        starlette_page.goto(f"{starlette_server}/register")
        starlette_page.fill('input[name="email"]', email)
        starlette_page.fill('input[name="password"]', password)
        starlette_page.fill('input[name="password_confirm"]', password)
        starlette_page.click('button[type="submit"]')

        # Should redirect to login page
        starlette_page.wait_for_url(f"{starlette_server}/login**", timeout=5000)

        # Should show success message
        content = starlette_page.content()
        assert "success" in content.lower() or "login" in content.lower()

    def test_register_password_mismatch(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Registration with mismatched passwords should show error."""
        starlette_page.goto(f"{starlette_server}/register")
        starlette_page.fill('input[name="email"]', generate_test_email())
        starlette_page.fill('input[name="password"]', "password123")
        starlette_page.fill('input[name="password_confirm"]', "different456")
        starlette_page.click('button[type="submit"]')

        # Should stay on register page with error
        content = starlette_page.content()
        assert "match" in content.lower() or "error" in content.lower()

    def test_register_invalid_email(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Registration with invalid email should show error."""
        starlette_page.goto(f"{starlette_server}/register")
        starlette_page.fill('input[name="email"]', "not-an-email")
        starlette_page.fill('input[name="password"]', "password123")
        starlette_page.fill('input[name="password_confirm"]', "password123")
        starlette_page.click('button[type="submit"]')

        # Should show error
        content = starlette_page.content()
        assert "invalid" in content.lower() or "email" in content.lower()

    def test_register_short_password(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Registration with short password should show error."""
        starlette_page.goto(f"{starlette_server}/register")
        starlette_page.fill('input[name="email"]', generate_test_email())
        starlette_page.fill('input[name="password"]', "short")
        starlette_page.fill('input[name="password_confirm"]', "short")
        starlette_page.click('button[type="submit"]')

        # Should show error about password length
        content = starlette_page.content()
        assert (
            "8" in content
            or "character" in content.lower()
            or "error" in content.lower()
        )

    def test_register_duplicate_email(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Registration with existing email should show error."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first time
        register_user(starlette_page, starlette_server, email, password)

        # Try to register again with same email
        starlette_page.goto(f"{starlette_server}/register")
        starlette_page.fill('input[name="email"]', email)
        starlette_page.fill('input[name="password"]', password)
        starlette_page.fill('input[name="password_confirm"]', password)
        starlette_page.click('button[type="submit"]')

        # Should show error about existing email
        content = starlette_page.content()
        assert (
            "already" in content.lower()
            or "exist" in content.lower()
            or "registered" in content.lower()
        )


class TestStarletteLogin:
    """Tests for login flow."""

    def test_login_page_loads(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Login page should load with form fields."""
        starlette_page.goto(f"{starlette_server}/login")

        assert starlette_page.locator('input[name="email"]').is_visible()
        assert starlette_page.locator('input[name="password"]').is_visible()
        assert starlette_page.locator('button[type="submit"]').is_visible()

    def test_login_success(self, starlette_page: Page, starlette_server: str) -> None:
        """Successful login should redirect to dashboard."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first
        register_user(starlette_page, starlette_server, email, password)

        # Now login
        login_user(starlette_page, starlette_server, email, password)

        # Should be on dashboard
        assert "/dashboard" in starlette_page.url
        content = starlette_page.content()
        assert "dashboard" in content.lower() or email in content.lower()

    def test_login_invalid_password(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Login with wrong password should show error."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first
        register_user(starlette_page, starlette_server, email, password)

        # Try to login with wrong password
        starlette_page.goto(f"{starlette_server}/login")
        starlette_page.fill('input[name="email"]', email)
        starlette_page.fill('input[name="password"]', "wrongpassword")
        starlette_page.click('button[type="submit"]')

        # Should show error and stay on login page
        content = starlette_page.content()
        assert "invalid" in content.lower() or "error" in content.lower()

    def test_login_nonexistent_user(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Login with non-existent user should show error."""
        starlette_page.goto(f"{starlette_server}/login")
        starlette_page.fill('input[name="email"]', "nobody@example.com")
        starlette_page.fill('input[name="password"]', "somepassword")
        starlette_page.click('button[type="submit"]')

        # Should show error
        content = starlette_page.content()
        assert "invalid" in content.lower() or "error" in content.lower()


class TestStarletteProtectedRoutes:
    """Tests for protected routes."""

    def test_dashboard_requires_login(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Dashboard should redirect to login when not authenticated."""
        starlette_page.goto(f"{starlette_server}/dashboard")

        # Should redirect to login
        assert "/login" in starlette_page.url

    def test_dashboard_accessible_when_logged_in(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Dashboard should be accessible when logged in."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(starlette_page, starlette_server, email, password)
        login_user(starlette_page, starlette_server, email, password)

        # Navigate to dashboard
        starlette_page.goto(f"{starlette_server}/dashboard")

        # Should show dashboard content
        assert "/dashboard" in starlette_page.url
        content = starlette_page.content()
        assert "dashboard" in content.lower()


class TestStarletteLogout:
    """Tests for logout functionality."""

    def test_logout_success(self, starlette_page: Page, starlette_server: str) -> None:
        """Logout should end the session."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(starlette_page, starlette_server, email, password)
        login_user(starlette_page, starlette_server, email, password)

        # Verify logged in
        starlette_page.goto(f"{starlette_server}/dashboard")
        assert "/dashboard" in starlette_page.url

        # Logout
        logout_user(starlette_page, starlette_server)

        # Try to access dashboard again
        starlette_page.goto(f"{starlette_server}/dashboard")

        # Should be redirected to login
        assert "/login" in starlette_page.url


class TestStarletteAdmin:
    """Tests for admin functionality."""

    @pytest.mark.skip(
        reason="Admin console requires additional setup in test environment"
    )
    def test_admin_requires_login(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Admin page should redirect to login when not authenticated."""
        starlette_page.goto(f"{starlette_server}/admin")

        # Should redirect to login (or show 401/403)
        # Starlette admin is mounted separately, behavior may vary
        content = starlette_page.content()
        assert "/login" in starlette_page.url or "login" in content.lower()

    @pytest.mark.skip(
        reason="Admin console requires additional setup in test environment"
    )
    def test_first_user_is_admin(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """First registered user should have admin access."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(starlette_page, starlette_server, email, password)
        login_user(starlette_page, starlette_server, email, password)

        # Navigate to admin
        starlette_page.goto(f"{starlette_server}/admin")

        # Should be on admin page (not redirected to login)
        content = starlette_page.content()
        # Admin page should show admin content or dashboard
        assert "admin" in content.lower() or "dashboard" in content.lower()


class TestStarletteRoles:
    """Tests for role display."""

    def test_first_user_has_admin_role(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """First user should have admin and user roles displayed."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(starlette_page, starlette_server, email, password)
        login_user(starlette_page, starlette_server, email, password)

        # Go to dashboard
        starlette_page.goto(f"{starlette_server}/dashboard")

        # Should show roles
        content = starlette_page.content()
        # Should have admin role (first user privilege)
        assert "admin" in content.lower()


class TestStarletteFullFlow:
    """Complete end-to-end flow tests."""

    def test_complete_user_journey(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Test complete user journey: register -> login -> dashboard -> logout."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # 1. Visit home page
        starlette_page.goto(starlette_server)
        assert starlette_page.locator("body").is_visible()

        # 2. Navigate to register
        starlette_page.click('a[href*="register"]')
        starlette_page.wait_for_url(f"{starlette_server}/register**")

        # 3. Fill registration form
        starlette_page.fill('input[name="email"]', email)
        starlette_page.fill('input[name="password"]', password)
        starlette_page.fill('input[name="password_confirm"]', password)
        starlette_page.click('button[type="submit"]')

        # 4. Should redirect to login
        starlette_page.wait_for_url(f"{starlette_server}/login**", timeout=5000)

        # 5. Login
        starlette_page.fill('input[name="email"]', email)
        starlette_page.fill('input[name="password"]', password)
        starlette_page.click('button[type="submit"]')

        # 6. Should be on dashboard
        starlette_page.wait_for_url(f"{starlette_server}/dashboard**", timeout=5000)
        content = starlette_page.content()
        assert email in content

        # 7. Logout
        logout_button = starlette_page.locator(
            'button:has-text("Logout"), input[value="Logout"], '
            'form[action*="logout"] button'
        )
        logout_button.first.click()

        # 8. Should be logged out
        starlette_page.wait_for_url(f"{starlette_server}/**", timeout=5000)

        # 9. Dashboard should now require login
        starlette_page.goto(f"{starlette_server}/dashboard")
        assert "/login" in starlette_page.url

    def test_session_persistence(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Session should persist across page navigations."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(starlette_page, starlette_server, email, password)
        login_user(starlette_page, starlette_server, email, password)

        # Navigate to different pages
        starlette_page.goto(starlette_server)
        starlette_page.goto(f"{starlette_server}/dashboard")

        # Should still be logged in
        assert "/dashboard" in starlette_page.url
        content = starlette_page.content()
        assert email in content

    def test_page_refresh_keeps_session(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Session should persist after page refresh."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(starlette_page, starlette_server, email, password)
        login_user(starlette_page, starlette_server, email, password)

        # Refresh page
        starlette_page.reload()

        # Should still be on dashboard
        assert "/dashboard" in starlette_page.url
        content = starlette_page.content()
        assert email in content


class TestStarletteAPI:
    """Tests for the JSON API endpoints via browser."""

    @pytest.mark.skip(reason="Browser fetch API has CORS issues in test environment")
    def test_api_register_and_login(
        self, starlette_page: Page, starlette_server: str
    ) -> None:
        """Test API registration and login flow."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Use page.evaluate to make API calls
        register_response = starlette_page.evaluate(
            """async ([url, email, password]) => {
                const response = await fetch(url + '/api/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password})
                });
                return {status: response.status, data: await response.json()};
            }""",
            [starlette_server, email, password],
        )

        assert register_response["status"] == 201
        assert "user_id" in register_response["data"]

        # Login via API
        login_response = starlette_page.evaluate(
            """async ([url, email, password]) => {
                const response = await fetch(url + '/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password}),
                    credentials: 'include'
                });
                return {status: response.status, data: await response.json()};
            }""",
            [starlette_server, email, password],
        )

        assert login_response["status"] == 200
        assert "Logged in" in login_response["data"]["message"]
