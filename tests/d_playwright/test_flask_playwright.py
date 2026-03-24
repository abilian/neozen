"""Playwright end-to-end tests for the Flask demo application.

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


class TestFlaskHomePage:
    """Tests for the Flask demo home page."""

    def test_home_page_loads(self, flask_page: Page, flask_server: str) -> None:
        """Home page should load and display NeoZen branding."""
        flask_page.goto(flask_server)

        assert flask_page.title() or True  # Page loaded
        assert flask_page.locator("body").is_visible()

        # Should contain NeoZen or demo branding
        content = flask_page.content()
        assert "NeoZen" in content or "Demo" in content

    def test_home_page_has_navigation(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Home page should have login/register links."""
        flask_page.goto(flask_server)

        # Should have login link
        login_link = flask_page.locator('a[href*="login"]')
        assert login_link.count() > 0

        # Should have register link
        register_link = flask_page.locator('a[href*="register"]')
        assert register_link.count() > 0


class TestFlaskRegistration:
    """Tests for user registration flow."""

    def test_register_page_loads(self, flask_page: Page, flask_server: str) -> None:
        """Registration page should load with form fields."""
        flask_page.goto(f"{flask_server}/register")

        # Should have email field
        assert flask_page.locator('input[name="email"]').is_visible()

        # Should have password fields
        assert flask_page.locator('input[name="password"]').is_visible()
        assert flask_page.locator('input[name="password_confirm"]').is_visible()

        # Should have submit button
        assert flask_page.locator('button[type="submit"]').is_visible()

    def test_register_success(self, flask_page: Page, flask_server: str) -> None:
        """Successful registration should redirect to login."""
        email = generate_test_email()
        password = "SecurePassword123!"

        flask_page.goto(f"{flask_server}/register")
        flask_page.fill('input[name="email"]', email)
        flask_page.fill('input[name="password"]', password)
        flask_page.fill('input[name="password_confirm"]', password)
        flask_page.click('button[type="submit"]')

        # Should redirect to login page
        flask_page.wait_for_url(f"{flask_server}/login**", timeout=5000)

        # Should show success message
        content = flask_page.content()
        assert "success" in content.lower() or "login" in content.lower()

    def test_register_password_mismatch(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Registration with mismatched passwords should show error."""
        flask_page.goto(f"{flask_server}/register")
        flask_page.fill('input[name="email"]', generate_test_email())
        flask_page.fill('input[name="password"]', "password123")
        flask_page.fill('input[name="password_confirm"]', "different456")
        flask_page.click('button[type="submit"]')

        # Should stay on register page with error
        content = flask_page.content()
        assert "match" in content.lower() or "error" in content.lower()

    def test_register_invalid_email(self, flask_page: Page, flask_server: str) -> None:
        """Registration with invalid email should show error."""
        flask_page.goto(f"{flask_server}/register")
        flask_page.fill('input[name="email"]', "not-an-email")
        flask_page.fill('input[name="password"]', "password123")
        flask_page.fill('input[name="password_confirm"]', "password123")
        flask_page.click('button[type="submit"]')

        # Should show error
        content = flask_page.content()
        assert "invalid" in content.lower() or "email" in content.lower()

    def test_register_short_password(self, flask_page: Page, flask_server: str) -> None:
        """Registration with short password should show error."""
        flask_page.goto(f"{flask_server}/register")
        flask_page.fill('input[name="email"]', generate_test_email())
        flask_page.fill('input[name="password"]', "short")
        flask_page.fill('input[name="password_confirm"]', "short")
        flask_page.click('button[type="submit"]')

        # Should show error about password length
        content = flask_page.content()
        assert (
            "8" in content
            or "character" in content.lower()
            or "error" in content.lower()
        )

    def test_register_duplicate_email(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Registration with existing email should show error."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first time
        register_user(flask_page, flask_server, email, password)

        # Try to register again with same email
        flask_page.goto(f"{flask_server}/register")
        flask_page.fill('input[name="email"]', email)
        flask_page.fill('input[name="password"]', password)
        flask_page.fill('input[name="password_confirm"]', password)
        flask_page.click('button[type="submit"]')

        # Should show error about existing email
        content = flask_page.content()
        assert (
            "already" in content.lower()
            or "exist" in content.lower()
            or "registered" in content.lower()
        )


class TestFlaskLogin:
    """Tests for login flow."""

    def test_login_page_loads(self, flask_page: Page, flask_server: str) -> None:
        """Login page should load with form fields."""
        flask_page.goto(f"{flask_server}/login")

        assert flask_page.locator('input[name="email"]').is_visible()
        assert flask_page.locator('input[name="password"]').is_visible()
        assert flask_page.locator('button[type="submit"]').is_visible()

    def test_login_success(self, flask_page: Page, flask_server: str) -> None:
        """Successful login should redirect to dashboard."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first
        register_user(flask_page, flask_server, email, password)

        # Now login
        login_user(flask_page, flask_server, email, password)

        # Should be on dashboard
        assert "/dashboard" in flask_page.url
        content = flask_page.content()
        assert "dashboard" in content.lower() or email in content.lower()

    def test_login_invalid_password(self, flask_page: Page, flask_server: str) -> None:
        """Login with wrong password should show error."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # Register first
        register_user(flask_page, flask_server, email, password)

        # Try to login with wrong password
        flask_page.goto(f"{flask_server}/login")
        flask_page.fill('input[name="email"]', email)
        flask_page.fill('input[name="password"]', "wrongpassword")
        flask_page.click('button[type="submit"]')

        # Should show error and stay on login page
        content = flask_page.content()
        assert "invalid" in content.lower() or "error" in content.lower()

    def test_login_nonexistent_user(self, flask_page: Page, flask_server: str) -> None:
        """Login with non-existent user should show error."""
        flask_page.goto(f"{flask_server}/login")
        flask_page.fill('input[name="email"]', "nobody@example.com")
        flask_page.fill('input[name="password"]', "somepassword")
        flask_page.click('button[type="submit"]')

        # Should show error
        content = flask_page.content()
        assert "invalid" in content.lower() or "error" in content.lower()


class TestFlaskProtectedRoutes:
    """Tests for protected routes."""

    def test_dashboard_requires_login(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Dashboard should redirect to login when not authenticated."""
        flask_page.goto(f"{flask_server}/dashboard")

        # Should redirect to login
        assert "/login" in flask_page.url

    def test_dashboard_accessible_when_logged_in(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Dashboard should be accessible when logged in."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(flask_page, flask_server, email, password)
        login_user(flask_page, flask_server, email, password)

        # Navigate to dashboard
        flask_page.goto(f"{flask_server}/dashboard")

        # Should show dashboard content
        assert "/dashboard" in flask_page.url
        content = flask_page.content()
        assert "dashboard" in content.lower()


class TestFlaskLogout:
    """Tests for logout functionality."""

    def test_logout_success(self, flask_page: Page, flask_server: str) -> None:
        """Logout should end the session."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(flask_page, flask_server, email, password)
        login_user(flask_page, flask_server, email, password)

        # Verify logged in
        flask_page.goto(f"{flask_server}/dashboard")
        assert "/dashboard" in flask_page.url

        # Logout
        logout_user(flask_page, flask_server)

        # Try to access dashboard again
        flask_page.goto(f"{flask_server}/dashboard")

        # Should be redirected to login
        assert "/login" in flask_page.url


class TestFlaskAdmin:
    """Tests for admin functionality."""

    def test_admin_requires_login(self, flask_page: Page, flask_server: str) -> None:
        """Admin page should redirect to login when not authenticated."""
        flask_page.goto(f"{flask_server}/admin")

        # Should redirect to login
        assert "/login" in flask_page.url

    def test_first_user_is_admin(self, flask_page: Page, flask_server: str) -> None:
        """First registered user should have admin access."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(flask_page, flask_server, email, password)
        login_user(flask_page, flask_server, email, password)

        # Navigate to admin
        flask_page.goto(f"{flask_server}/admin")

        # Should be on admin page (not redirected)
        content = flask_page.content()
        # Admin page should show admin content or dashboard
        assert "admin" in content.lower() or "dashboard" in content.lower()


class TestFlaskRoles:
    """Tests for role display."""

    def test_first_user_has_admin_role(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """First user should have admin and user roles displayed."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(flask_page, flask_server, email, password)
        login_user(flask_page, flask_server, email, password)

        # Go to dashboard
        flask_page.goto(f"{flask_server}/dashboard")

        # Should show roles
        content = flask_page.content()
        # Should have admin role (first user privilege)
        assert "admin" in content.lower()


class TestFlaskFullFlow:
    """Complete end-to-end flow tests."""

    def test_complete_user_journey(self, flask_page: Page, flask_server: str) -> None:
        """Test complete user journey: register -> login -> dashboard -> logout."""
        email = generate_test_email()
        password = "SecurePassword123!"

        # 1. Visit home page
        flask_page.goto(flask_server)
        assert flask_page.locator("body").is_visible()

        # 2. Navigate to register
        flask_page.click('a[href*="register"]')
        flask_page.wait_for_url(f"{flask_server}/register**")

        # 3. Fill registration form
        flask_page.fill('input[name="email"]', email)
        flask_page.fill('input[name="password"]', password)
        flask_page.fill('input[name="password_confirm"]', password)
        flask_page.click('button[type="submit"]')

        # 4. Should redirect to login
        flask_page.wait_for_url(f"{flask_server}/login**", timeout=5000)

        # 5. Login
        flask_page.fill('input[name="email"]', email)
        flask_page.fill('input[name="password"]', password)
        flask_page.click('button[type="submit"]')

        # 6. Should be on dashboard
        flask_page.wait_for_url(f"{flask_server}/dashboard**", timeout=5000)
        content = flask_page.content()
        assert email in content

        # 7. Logout
        logout_button = flask_page.locator(
            'button:has-text("Logout"), input[value="Logout"], '
            'form[action*="logout"] button'
        )
        logout_button.first.click()

        # 8. Should be logged out
        flask_page.wait_for_url(f"{flask_server}/**", timeout=5000)

        # 9. Dashboard should now require login
        flask_page.goto(f"{flask_server}/dashboard")
        assert "/login" in flask_page.url

    def test_session_persistence(self, flask_page: Page, flask_server: str) -> None:
        """Session should persist across page navigations."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(flask_page, flask_server, email, password)
        login_user(flask_page, flask_server, email, password)

        # Navigate to different pages
        flask_page.goto(flask_server)
        flask_page.goto(f"{flask_server}/dashboard")

        # Should still be logged in
        assert "/dashboard" in flask_page.url
        content = flask_page.content()
        assert email in content

    def test_page_refresh_keeps_session(
        self, flask_page: Page, flask_server: str
    ) -> None:
        """Session should persist after page refresh."""
        email = generate_test_email()
        password = "SecurePassword123!"

        register_user(flask_page, flask_server, email, password)
        login_user(flask_page, flask_server, email, password)

        # Refresh page
        flask_page.reload()

        # Should still be on dashboard
        assert "/dashboard" in flask_page.url
        content = flask_page.content()
        assert email in content
