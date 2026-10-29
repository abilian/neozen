"""SCIM Users endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from neozen.core.scim.models import User, parse_resource

if TYPE_CHECKING:
    from neozen.core.scim.service import SCIMUserService


class UsersEndpoint:
    """HTTP adapter for /Users.

    Handles all CRUD operations for SCIM users:
    - GET /Users -> list (with filter, pagination)
    - GET /Users/{id} -> get
    - POST /Users -> create
    - PUT /Users/{id} -> replace
    - DELETE /Users/{id} -> delete

    Example:
        endpoint = UsersEndpoint(user_service)

        # GET /Users?filter=userName%20eq%20%22alice%22&count=10
        result = await endpoint.list(query_params)

        # POST /Users
        result = await endpoint.create(json_body)

        # GET /Users/{id}
        result = await endpoint.get("user_123")
    """

    def __init__(self, service: SCIMUserService) -> None:
        self.service = service

    async def list(self, query_params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Handle GET /Users with optional filter and pagination."""
        params = query_params or {}
        try:
            start_index = int(params.get("startIndex", 1))
        except (TypeError, ValueError):
            start_index = 1
        try:
            count = int(params.get("count", 100))
        except (TypeError, ValueError):
            count = 100

        filter_expr = params.get("filter")
        result = await self.service.list_users(
            filter_expr=filter_expr,
            start_index=start_index,
            count=count,
        )
        return result.to_dict()

    async def get(self, user_id: str) -> dict[str, Any]:
        """Handle GET /Users/{id}."""
        user = await self.service.get_user(user_id)
        return user.to_dict()

    async def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle POST /Users."""
        user = parse_resource(User.from_dict, payload)
        created = await self.service.create_user(user)
        return created.to_dict()

    async def replace(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle PUT /Users/{id}."""
        user = parse_resource(User.from_dict, payload)
        updated = await self.service.update_user(user_id, user)
        return updated.to_dict()

    async def delete(self, user_id: str) -> None:
        """Handle DELETE /Users/{id}."""
        await self.service.delete_user(user_id)


__all__ = ["UsersEndpoint"]
