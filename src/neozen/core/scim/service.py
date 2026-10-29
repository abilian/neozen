"""SCIM service layer.

Provides SCIM operations (CRUD, list, filter, paginate) on top of
adapter protocols. Consumers implement adapters that bridge their
own User/Group models to the SCIM resource format.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from neozen.core.scim.errors import (
    SCIMNotFoundError,
    SCIMUniquenessError,
    SCIMValidationError,
)
from neozen.core.scim.filter_parser import (
    FilterExpression,
    parse_filter,
)
from neozen.core.scim.models import (
    Group,
    ListResponse,
    Meta,
    User,
)

# The most resources one list response returns, advertised as
# filter.maxResults in /ServiceProviderConfig.
MAX_RESULTS = 200


def _page[T](items: list[T], start_index: int, count: int) -> list[T]:
    """One page of a list (RFC 7644 §3.4.2.4).

    ``count`` is clamped to [0, MAX_RESULTS]: 0 returns no resources, only
    the total.
    """
    offset = max(start_index, 1) - 1
    return items[offset : offset + min(max(count, 0), MAX_RESULTS)]


class SubjectAdapter(Protocol):
    """Adapter for bridging an application's User model to SCIM.

    Implementations translate between the app's User model and
    SCIM User resources, and provide CRUD operations.
    """

    async def create(self, user: User) -> User:
        """Create a new user. Should raise SCIMUniquenessError if
        the userName or email is already taken."""
        ...

    async def get(self, user_id: str) -> User | None:
        """Look up a user by ID. Returns None if not found."""
        ...

    async def get_by_username(self, user_name: str) -> User | None:
        """Look up a user by userName. Returns None if not found."""
        ...

    async def update(self, user_id: str, user: User) -> User:
        """Replace a user. Raises SCIMNotFoundError if missing."""
        ...

    async def delete(self, user_id: str) -> None:
        """Delete a user. Raises SCIMNotFoundError if missing."""
        ...

    async def list_all(self) -> list[User]:
        """List all users. The service handles filter/pagination."""
        ...


class GroupAdapter(Protocol):
    """Adapter for bridging an application's Group model to SCIM."""

    async def create(self, group: Group) -> Group: ...

    async def get(self, group_id: str) -> Group | None: ...

    async def get_by_display_name(self, display_name: str) -> Group | None: ...

    async def update(self, group_id: str, group: Group) -> Group: ...

    async def delete(self, group_id: str) -> None: ...

    async def list_all(self) -> list[Group]: ...


def _populate_meta(
    resource: User | Group,
    *,
    resource_type: str,
    base_url: str = "",
    created: datetime | None = None,
) -> None:
    """Set the meta field on a resource if not already set."""
    now = datetime.now(UTC)
    location = (
        f"{base_url.rstrip('/')}/{resource_type}s/{resource.id}"
        if resource.id and base_url
        else None
    )
    if resource.meta is None:
        resource.meta = Meta(
            resource_type=resource_type,
            created=created or now,
            last_modified=now,
            location=location,
        )
    else:
        resource.meta = Meta(
            resource_type=resource_type,
            created=resource.meta.created or created or now,
            last_modified=now,
            location=location or resource.meta.location,
            version=resource.meta.version,
        )


class SCIMUserService:
    """SCIM user operations.

    Wraps a `SubjectAdapter` and adds:
    - List with filter, pagination
    - Meta population
    - Validation

    Example:
        service = SCIMUserService(
            adapter=my_adapter,
            base_url="https://api.example.com/scim/v2",
        )
        result = await service.list_users(
            filter_expr='userName sw "alice"',
            start_index=1,
            count=10,
        )
    """

    def __init__(
        self,
        adapter: SubjectAdapter,
        *,
        base_url: str = "",
    ) -> None:
        self.adapter = adapter
        self.base_url = base_url

    async def create_user(self, user: User) -> User:
        if not user.user_name:
            msg = "userName is required"
            raise SCIMValidationError(msg)

        # Check uniqueness
        existing = await self.adapter.get_by_username(user.user_name)
        if existing is not None:
            msg = f"userName '{user.user_name}' already exists"
            raise SCIMUniquenessError(msg)

        created = await self.adapter.create(user)
        _populate_meta(created, resource_type="User", base_url=self.base_url)
        return created

    async def get_user(self, user_id: str) -> User:
        user = await self.adapter.get(user_id)
        if user is None:
            msg = f"User {user_id} not found"
            raise SCIMNotFoundError(msg)
        _populate_meta(user, resource_type="User", base_url=self.base_url)
        return user

    async def update_user(self, user_id: str, user: User) -> User:
        existing = await self.adapter.get(user_id)
        if existing is None:
            msg = f"User {user_id} not found"
            raise SCIMNotFoundError(msg)

        # If userName changed, check uniqueness
        if user.user_name and user.user_name != existing.user_name:
            other = await self.adapter.get_by_username(user.user_name)
            if other is not None and other.id != user_id:
                msg = f"userName '{user.user_name}' already exists"
                raise SCIMUniquenessError(msg)

        # Preserve ID
        user.id = user_id
        updated = await self.adapter.update(user_id, user)
        _populate_meta(updated, resource_type="User", base_url=self.base_url)
        return updated

    async def delete_user(self, user_id: str) -> None:
        existing = await self.adapter.get(user_id)
        if existing is None:
            msg = f"User {user_id} not found"
            raise SCIMNotFoundError(msg)
        await self.adapter.delete(user_id)

    async def list_users(
        self,
        *,
        filter_expr: str | None = None,
        start_index: int = 1,
        count: int = 100,
    ) -> ListResponse:
        """List users with optional filter and pagination.

        Args:
            filter_expr: SCIM filter string (e.g., `userName eq "alice"`).
            start_index: 1-based index of the first result.
            count: Maximum number of results to return, at most
                ``MAX_RESULTS``.
        """
        all_users = await self.adapter.list_all()

        # Apply filter
        filtered: list[User]
        if filter_expr:
            expr = parse_filter(filter_expr)
            filtered = [u for u in all_users if _matches_filter(expr, u)]
        else:
            filtered = list(all_users)

        page = _page(filtered, start_index, count)

        # Populate meta on returned items
        for u in page:
            _populate_meta(u, resource_type="User", base_url=self.base_url)

        return ListResponse(
            resources=page,
            total_results=len(filtered),
            start_index=max(start_index, 1),
            items_per_page=len(page),
        )


class SCIMGroupService:
    """SCIM group operations."""

    def __init__(
        self,
        adapter: GroupAdapter,
        *,
        base_url: str = "",
    ) -> None:
        self.adapter = adapter
        self.base_url = base_url

    async def create_group(self, group: Group) -> Group:
        if not group.display_name:
            msg = "displayName is required"
            raise SCIMValidationError(msg)

        existing = await self.adapter.get_by_display_name(group.display_name)
        if existing is not None:
            msg = f"Group '{group.display_name}' already exists"
            raise SCIMUniquenessError(msg)

        created = await self.adapter.create(group)
        _populate_meta(created, resource_type="Group", base_url=self.base_url)
        return created

    async def get_group(self, group_id: str) -> Group:
        group = await self.adapter.get(group_id)
        if group is None:
            msg = f"Group {group_id} not found"
            raise SCIMNotFoundError(msg)
        _populate_meta(group, resource_type="Group", base_url=self.base_url)
        return group

    async def update_group(self, group_id: str, group: Group) -> Group:
        existing = await self.adapter.get(group_id)
        if existing is None:
            msg = f"Group {group_id} not found"
            raise SCIMNotFoundError(msg)

        if group.display_name and group.display_name != existing.display_name:
            other = await self.adapter.get_by_display_name(group.display_name)
            if other is not None and other.id != group_id:
                msg = f"Group '{group.display_name}' already exists"
                raise SCIMUniquenessError(msg)

        group.id = group_id
        updated = await self.adapter.update(group_id, group)
        _populate_meta(updated, resource_type="Group", base_url=self.base_url)
        return updated

    async def delete_group(self, group_id: str) -> None:
        existing = await self.adapter.get(group_id)
        if existing is None:
            msg = f"Group {group_id} not found"
            raise SCIMNotFoundError(msg)
        await self.adapter.delete(group_id)

    async def list_groups(
        self,
        *,
        filter_expr: str | None = None,
        start_index: int = 1,
        count: int = 100,
    ) -> ListResponse:
        all_groups = await self.adapter.list_all()

        filtered: list[Group]
        if filter_expr:
            expr = parse_filter(filter_expr)
            filtered = [g for g in all_groups if _matches_filter(expr, g)]
        else:
            filtered = list(all_groups)

        page = _page(filtered, start_index, count)

        for g in page:
            _populate_meta(g, resource_type="Group", base_url=self.base_url)

        return ListResponse(
            resources=page,
            total_results=len(filtered),
            start_index=max(start_index, 1),
            items_per_page=len(page),
        )


def _matches_filter(expr: FilterExpression, item: Any) -> bool:
    """Helper that handles all FilterExpression subtypes."""
    return bool(expr.matches(item))


__all__ = [
    "GroupAdapter",
    "SCIMGroupService",
    "SCIMUserService",
    "SubjectAdapter",
]
