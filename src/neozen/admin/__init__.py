"""NeoZen Admin UI.

A Litestar-based administration interface for managing:
- Subjects (users)
- Roles and permissions
- Sessions

Usage:
    from neozen.admin import create_admin_app, AdminConfig

    config = AdminConfig(
        db_url="sqlite+aiosqlite:///data/neozen.db",
        secret_key="your-secret-key",
    )
    app = create_admin_app(config)

Or run standalone:
    uvicorn neozen.admin.app:create_admin_app --factory --port 8080
"""

from __future__ import annotations

from neozen.admin.app import create_admin_app
from neozen.admin.config import AdminConfig
from neozen.admin.services import AdminService, DashboardStats

__all__ = [
    "AdminConfig",
    "AdminService",
    "DashboardStats",
    "create_admin_app",
]
