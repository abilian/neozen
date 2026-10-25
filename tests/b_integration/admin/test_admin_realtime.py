"""Endpoint smoke tests for the admin real-time live-tail endpoints.

Covers /audit/tail, /security/stats, and /dashboard/stats — the three
HTMX polling endpoints introduced for the 1.0 admin real-time-updates
work. Also verifies that the parent pages render the polling
attributes that hook them up.
"""

from __future__ import annotations

import pytest
from litestar.testing import TestClient

from neozen.admin.app import create_admin_app
from neozen.admin.config import AdminConfig

from .conftest import superadmin_client


@pytest.fixture
def admin_client() -> TestClient:
    config = AdminConfig(
        db_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
    )
    return superadmin_client(create_admin_app(config))


# =============================================================================
# Audit log live tail
# =============================================================================


class TestAuditLogTail:
    def test_tail_endpoint_returns_partial(self, admin_client: TestClient) -> None:
        with admin_client as client:
            response = client.get("/audit/tail")
        assert response.status_code == 200
        body = response.text
        # Wrapping div with the polling-target id
        assert 'id="audit-log-table"' in body
        # Polling attributes are present (live=True)
        assert 'hx-get="/audit/tail"' in body
        assert 'hx-trigger="every 10s"' in body
        # Live indicator
        assert "Live" in body
        # No filter form, no breadcrumbs (it's a partial, not a full page)
        assert "Apply Filters" not in body

    def test_audit_list_page_enables_polling_when_no_filters(
        self, admin_client: TestClient
    ) -> None:
        with admin_client as client:
            response = client.get("/audit")
        assert response.status_code == 200
        body = response.text
        assert 'id="audit-log-table"' in body
        # Polling attributes present on the embedded partial
        assert 'hx-get="/audit/tail"' in body

    def test_audit_list_page_disables_polling_with_filters(
        self, admin_client: TestClient
    ) -> None:
        with admin_client as client:
            response = client.get("/audit?event_type=auth")
        assert response.status_code == 200
        body = response.text
        # The container is still there, but without polling attributes
        assert 'id="audit-log-table"' in body
        assert 'hx-get="/audit/tail"' not in body

    def test_audit_list_page_disables_polling_on_page_2(
        self, admin_client: TestClient
    ) -> None:
        with admin_client as client:
            response = client.get("/audit?page=2")
        assert response.status_code == 200
        body = response.text
        assert 'id="audit-log-table"' in body
        assert 'hx-get="/audit/tail"' not in body


# =============================================================================
# Security dashboard counters
# =============================================================================


class TestSecurityStats:
    def test_stats_endpoint_returns_partial(self, admin_client: TestClient) -> None:
        with admin_client as client:
            response = client.get("/security/stats")
        assert response.status_code == 200
        body = response.text
        assert 'id="security-stats"' in body
        assert 'hx-get="/security/stats"' in body
        assert 'hx-trigger="every 15s"' in body
        # All four counter labels are present
        assert "Events (7 days)" in body
        assert "Failed Events" in body
        assert "Active Sessions" in body
        assert "MFA Adoption" in body

    def test_security_dashboard_includes_polling_partial(
        self, admin_client: TestClient
    ) -> None:
        with admin_client as client:
            response = client.get("/security")
        assert response.status_code == 200
        body = response.text
        assert 'id="security-stats"' in body
        assert 'hx-get="/security/stats"' in body


# =============================================================================
# Main dashboard counters
# =============================================================================


class TestDashboardStats:
    def test_stats_endpoint_returns_partial(self, admin_client: TestClient) -> None:
        with admin_client as client:
            response = client.get("/dashboard/stats")
        assert response.status_code == 200
        body = response.text
        assert 'id="dashboard-stats"' in body
        assert 'hx-get="/dashboard/stats"' in body
        assert 'hx-trigger="every 15s"' in body
        # Four counter labels
        assert "Total Users" in body
        assert "Active Sessions" in body
        assert "Total Roles" in body
        assert "Role Assignments" in body

    def test_main_dashboard_includes_polling_partial(
        self, admin_client: TestClient
    ) -> None:
        with admin_client as client:
            response = client.get("/")
        assert response.status_code == 200
        body = response.text
        assert 'id="dashboard-stats"' in body
        assert 'hx-get="/dashboard/stats"' in body
