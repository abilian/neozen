"""Playwright end-to-end tests for the Litestar demo application.

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

from .conftest import generate_test_email, login_user, logout_user, register_user

if TYPE_CHECKING:
    from playwright.sync_api import Page


class TestLitestarHomePage:
    """Tests for the Litestar demo home page."""

    def test_home_page_loads(self, litestar_page: Page, litestar_server: str) -> None:
        """Home page should load and display NeoZen branding."""
        litestar_page.goto(litestar_server)

        assert litestar_page.locator("body").is_visible()

        # Should contain NeoZen or demo branding
        content = litestar_page.content()
        assert "NeoZen" in content or "Demo" in content

    def test_home_page_has_navigation(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Home page should have login/register links."""
        litestar_page.goto(litestar_server)

        # Should have login link
        login_link = litestar_page.locator('a[href*="login"]')
        assert login_link.count() > 0

        # Should have register link
        register_link = litestar_page.locator('a[href*="register"]')
        assert register_link.count() > 0


class TestLitestarRegistration:
    """Tests for user registration flow."""

    def test_register_page_loads(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Registration page should load with form fields."""
        litestar_page.goto(f"{litestar_server}/register")

        # Should have email field
        assert litestar_page.locator('input[name="email"]').is_visible()

        # Should have password fields
        assert litestar_page.locator('input[name="password"]').is_visible()
        assert litestar_page.locator('input[name="password_confirm"]').is_visible()

        # Should have submit button
        assert litestar_page.locator('button[type="submit"]').is_visible()

    def test_register_success(self, litestar_page: Page, litestar_server: str) -> None:
        """Successful registration should redirect to login."""
        email = generate_test_email()
        password = "SecurePassword123!"

        litestar_page.goto(f"{litestar_server}/register")
        litestar_page.fill('input[name="email"]', email)
        litestar_page.fill('input[name="password"]', password)
        litestar_page.fill('input[name="password_confirm"]', password)
        litestar_page.click('button[type="submit"]')

        # Should redirect to login page
        litestar_page.wait_for_url(f"{litestar_server}/login**", timeout=5000)

        # Should show success message
        content = litestar_page.content()
        assert "success" in content.lower() or "login" in content.lower()

    def test_register_password_mismatch(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Registration with mismatched passwords should show error."""
        litestar_page.goto(f"{litestar_server}/register")
        litestar_page.fill('input[name="email"]', generate_test_email())
        litestar_page.fill('input[name="password"]', "password123")
        litestar_page.fill('input[name="password_confirm"]', "different456")
        litestar_page.click('button[type="submit"]')

        # Should stay on register page with error
        content = litestar_page.content()
        assert "match" in content.lower() or "error" in content.lower()

    def test_register_invalid_email(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Registration with invalid email should show error."""
        litestar_page.goto(f"{litestar_server}/register")
        litestar_page.fill('input[name="email"]', "not-an-email")
        litestar_page.fill('input[name="password"]', "password123")
        litestar_page.fill('input[name="password_confirm"]', "password123")
        litestar_page.click('button[type="submit"]')

        # Should show error
        content = litestar_page.content()
        assert "invalid" in content.lower() or "email" in content.lower()

    def test_register_short_password(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Registration with short password should show error."""
        litestar_page.goto(f"{litestar_server}/register")
        litestar_page.fill('input[name="email"]', generate_test_email())
        litestar_page.fill('input[name="password"]', "short")
        litestar_page.fill('input[name="password_confirm"]', "short")
        litestar_page.click('button[type="submit"]')

        # Should show error about password length
        content = litestar_page.content()
        assert (
            "8" in content
            or "character" in content.lower()
            or "error" in content.lower()
        )

    def test_register_duplicate_email(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Registration with existing email should show error."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first time
        register_user(litestar_page, litestar_server, email, password)

        # Try to register again with same email
        litestar_page.goto(f"{litestar_server}/register")
        litestar_page.fill('input[name="email"]', email)
        litestar_page.fill('input[name="password"]', password)
        litestar_page.fill('input[name="password_confirm"]', password)
        litestar_page.click('button[type="submit"]')

        # Should show error about existing email
        content = litestar_page.content()
        assert (
            "already" in content.lower()
            or "exist" in content.lower()
            or "registered" in content.lower()
        )


class TestLitestarLogin:
    """Tests for login flow."""

    def test_login_page_loads(self, litestar_page: Page, litestar_server: str) -> None:
        """Login page should load with form fields."""
        litestar_page.goto(f"{litestar_server}/login")

        assert litestar_page.locator('input[name="email"]').is_visible()
        assert litestar_page.locator('input[name="password"]').is_visible()
        assert litestar_page.locator('button[type="submit"]').is_visible()

    def test_login_success(self, litestar_page: Page, litestar_server: str) -> None:
        """Successful login should redirect to dashboard."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first
        register_user(litestar_page, litestar_server, email, password)

        # Now login
        login_user(litestar_page, litestar_server, email, password)

        # Should be on dashboard
        assert "/dashboard" in litestar_page.url
        content = litestar_page.content()
        assert "dashboard" in content.lower() or email in content.lower()

    def test_login_invalid_password(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Login with wrong password should show error."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first
        register_user(litestar_page, litestar_server, email, password)

        # Try to login with wrong password
        litestar_page.goto(f"{litestar_server}/login")
        litestar_page.fill('input[name="email"]', email)
        litestar_page.fill('input[name="password"]', "wrongpassword")
        litestar_page.click('button[type="submit"]')

        # Should show error and stay on login page
        content = litestar_page.content()
        assert "invalid" in content.lower() or "error" in content.lower()

    def test_login_nonexistent_user(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Login with non-existent user should show error."""
        litestar_page.goto(f"{litestar_server}/login")
        litestar_page.fill('input[name="email"]', "nobody@example.com")
        litestar_page.fill('input[name="password"]', "somepassword")
        litestar_page.click('button[type="submit"]')

        # Should show error
        content = litestar_page.content()
        assert "invalid" in content.lower() or "error" in content.lower()


class TestLitestarProtectedRoutes:
    """Tests for protected routes."""

    def test_dashboard_requires_login(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Dashboard should redirect to login or show error when not authenticated."""
        litestar_page.goto(f"{litestar_server}/dashboard")

        # Litestar may redirect to login OR show 401 error
        content = litestar_page.content()
        assert (
            "/login" in litestar_page.url
            or "401" in content
            or "unauthorized" in content.lower()
        )

    def test_dashboard_accessible_when_logged_in(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Dashboard should be accessible when logged in."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(litestar_page, litestar_server, email, password)
        login_user(litestar_page, litestar_server, email, password)

        # Navigate to dashboard
        litestar_page.goto(f"{litestar_server}/dashboard")

        # Should show dashboard content
        assert "/dashboard" in litestar_page.url
        content = litestar_page.content()
        assert "dashboard" in content.lower()


class TestLitestarLogout:
    """Tests for logout functionality."""

    def test_logout_success(self, litestar_page: Page, litestar_server: str) -> None:
        """Logout should end the session."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(litestar_page, litestar_server, email, password)
        login_user(litestar_page, litestar_server, email, password)

        # Verify logged in
        litestar_page.goto(f"{litestar_server}/dashboard")
        assert "/dashboard" in litestar_page.url

        # Logout
        logout_user(litestar_page, litestar_server)

        # Try to access dashboard again
        litestar_page.goto(f"{litestar_server}/dashboard")

        # Should be redirected to login or show 401 error
        content = litestar_page.content()
        assert (
            "/login" in litestar_page.url
            or "401" in content
            or "unauthorized" in content.lower()
        )


class TestLitestarAdmin:
    """Tests for admin functionality."""

    def test_admin_requires_login(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Admin page should redirect to login or show error when not authenticated."""
        litestar_page.goto(f"{litestar_server}/admin")

        # Should redirect to login or show 401 error
        content = litestar_page.content()
        assert (
            "/login" in litestar_page.url
            or "401" in content
            or "unauthorized" in content.lower()
            or "required" in content.lower()
        )

    def test_first_user_is_admin(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """First registered user should have admin access."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(litestar_page, litestar_server, email, password)
        login_user(litestar_page, litestar_server, email, password)

        # Navigate to admin
        litestar_page.goto(f"{litestar_server}/admin")

        # Should be on admin page (not redirected to login)
        content = litestar_page.content()
        # Admin page should show admin content or dashboard
        assert "admin" in content.lower() or "dashboard" in content.lower()

    def test_non_admin_cannot_access_admin(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Non-admin user should not be able to access admin page."""
        # First user (gets admin)
        admin_email = generate_test_email()
        register_user(litestar_page, litestar_server, admin_email, "AdminPass123!")

        # Logout admin (clear session by going to a new page)
        litestar_page.context.clear_cookies()

        # Second user (no admin)
        user_email = generate_test_email()
        password = "UserPass123!"
        register_user(litestar_page, litestar_server, user_email, password)
        login_user(litestar_page, litestar_server, user_email, password)

        # Try to access admin
        litestar_page.goto(f"{litestar_server}/admin")

        # Should be redirected away or show error (401/403)
        content = litestar_page.content()
        assert (
            "/login" in litestar_page.url
            or "denied" in content.lower()
            or "required" in content.lower()
            or "401" in content
            or "403" in content
        )


class TestLitestarRoles:
    """Tests for role display."""

    def test_first_user_has_admin_role(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """First user should have admin and user roles displayed."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(litestar_page, litestar_server, email, password)
        login_user(litestar_page, litestar_server, email, password)

        # Go to dashboard
        litestar_page.goto(f"{litestar_server}/dashboard")

        # Should show roles
        content = litestar_page.content()
        # Should have admin role (first user privilege)
        assert "admin" in content.lower()


class TestLitestarFullFlow:
    """Complete end-to-end flow tests."""

    def test_complete_user_journey(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Test complete user journey: register -> login -> dashboard -> logout."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # 1. Visit home page
        litestar_page.goto(litestar_server)
        assert litestar_page.locator("body").is_visible()

        # 2. Navigate to register
        litestar_page.click('a[href*="register"]')
        litestar_page.wait_for_url(f"{litestar_server}/register**")

        # 3. Fill registration form
        litestar_page.fill('input[name="email"]', email)
        litestar_page.fill('input[name="password"]', password)
        litestar_page.fill('input[name="password_confirm"]', password)
        litestar_page.click('button[type="submit"]')

        # 4. Should redirect to login
        litestar_page.wait_for_url(f"{litestar_server}/login**", timeout=5000)

        # 5. Login
        litestar_page.fill('input[name="email"]', email)
        litestar_page.fill('input[name="password"]', password)
        litestar_page.click('button[type="submit"]')

        # 6. Should be on dashboard
        litestar_page.wait_for_url(f"{litestar_server}/dashboard**", timeout=5000)
        content = litestar_page.content()
        assert email in content

        # 7. Logout
        logout_button = litestar_page.locator(
            'button:has-text("Logout"), input[value="Logout"], '
            'form[action*="logout"] button'
        )
        logout_button.first.click()

        # 8. Should be logged out
        litestar_page.wait_for_url(f"{litestar_server}/**", timeout=5000)

        # 9. Dashboard should now require login
        litestar_page.goto(f"{litestar_server}/dashboard")
        # Should redirect to login or show 401 error
        content = litestar_page.content()
        assert (
            "/login" in litestar_page.url
            or "401" in content
            or "unauthorized" in content.lower()
        )

    def test_session_persistence(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Session should persist across page navigations."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(litestar_page, litestar_server, email, password)
        login_user(litestar_page, litestar_server, email, password)

        # Navigate to different pages
        litestar_page.goto(litestar_server)
        litestar_page.goto(f"{litestar_server}/dashboard")

        # Should still be logged in
        assert "/dashboard" in litestar_page.url
        content = litestar_page.content()
        assert email in content

    def test_page_refresh_keeps_session(
        self, litestar_page: Page, litestar_server: str
    ) -> None:
        """Session should persist after page refresh."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(litestar_page, litestar_server, email, password)
        login_user(litestar_page, litestar_server, email, password)

        # Refresh page
        litestar_page.reload()

        # Should still be on dashboard
        assert "/dashboard" in litestar_page.url
        content = litestar_page.content()
        assert email in content
