"""SCIM Groups endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from neozen.core.scim.errors import SCIMValidationError
from neozen.core.scim.models import Group

if TYPE_CHECKING:
    from neozen.core.scim.service import SCIMGroupService


class GroupsEndpoint:
    """HTTP adapter for /Groups."""

    def __init__(self, service: SCIMGroupService) -> None:
        self.service = service

    async def list(self, query_params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Handle GET /Groups."""
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
        result = await self.service.list_groups(
            filter_expr=filter_expr,
            start_index=start_index,
            count=count,
        )
        return result.to_dict()

    async def get(self, group_id: str) -> dict[str, Any]:
        group = await self.service.get_group(group_id)
        return group.to_dict()

    async def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            msg = "Request body must be a JSON object"
            raise SCIMValidationError(msg)
        try:
            group = Group.from_dict(payload)
        except KeyError as e:
            msg = f"Missing required field: {e}"
            raise SCIMValidationError(msg) from e
        created = await self.service.create_group(group)
        return created.to_dict()

    async def replace(self, group_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            msg = "Request body must be a JSON object"
            raise SCIMValidationError(msg)
        try:
            group = Group.from_dict(payload)
        except KeyError as e:
            msg = f"Missing required field: {e}"
            raise SCIMValidationError(msg) from e
        updated = await self.service.update_group(group_id, group)
        return updated.to_dict()

    async def delete(self, group_id: str) -> None:
        await self.service.delete_group(group_id)


__all__ = ["GroupsEndpoint"]
