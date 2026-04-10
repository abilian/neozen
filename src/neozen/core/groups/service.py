"""Group management service."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

from neozen.core.groups.models import (
    Group,
    GroupMembership,
    GroupMembershipRepository,
    GroupRepository,
    GroupRole,
)


class GroupError(Exception):
    """Base exception for group operations."""


class GroupNotFoundError(GroupError):
    """Raised when a group is not found."""


class GroupAlreadyExistsError(GroupError):
    """Raised when a group with the given name already exists."""


class NotAMemberError(GroupError):
    """Raised when a subject is not a member of a group."""


class InsufficientPermissionsError(GroupError):
    """Raised when an actor lacks permissions for an operation."""


class GroupService:
    """Service for group management.

    Handles:
    - Group CRUD
    - Adding/removing members
    - Changing membership roles
    - Permission checks (owner, admin, member)

    Example:
        service = GroupService(
            group_repository=group_repo,
            membership_repository=membership_repo,
        )

        group = await service.create_group(
            name="engineering",
            description="Engineering team",
            owner_id="user_123",
        )

        await service.add_member(group.id, "user_456", actor_id="user_123")
    """

    def __init__(
        self,
        group_repository: GroupRepository,
        membership_repository: GroupMembershipRepository,
    ) -> None:
        self.group_repository = group_repository
        self.membership_repository = membership_repository

    @staticmethod
    def _new_id(prefix: str) -> str:
        return f"{prefix}_{secrets.token_hex(8)}"

    # ----- Group CRUD -----

    async def create_group(
        self,
        name: str,
        *,
        description: str = "",
        owner_id: str | None = None,
    ) -> Group:
        """Create a new group.

        If `owner_id` is given, the creator is added as the OWNER.
        """
        existing = await self.group_repository.get_by_name(name)
        if existing is not None:
            msg = f"Group '{name}' already exists"
            raise GroupAlreadyExistsError(msg)

        now = datetime.now(UTC)
        group = await self.group_repository.create(
            id=self._new_id("grp"),
            name=name,
            description=description,
            created_at=now,
            created_by=owner_id,
        )

        if owner_id is not None:
            await self.membership_repository.create(
                id=self._new_id("mem"),
                group_id=group.id,
                subject_id=owner_id,
                role=GroupRole.OWNER.value,
                joined_at=now,
            )

        return group

    async def get_group(self, group_id: str) -> Group:
        group = await self.group_repository.get_by_id(group_id)
        if group is None:
            msg = f"Group not found: {group_id}"
            raise GroupNotFoundError(msg)
        return group

    async def get_group_by_name(self, name: str) -> Group | None:
        return await self.group_repository.get_by_name(name)

    async def list_groups(self) -> list[Group]:
        return await self.group_repository.list_all()

    async def update_group(
        self,
        group_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> Group:
        group = await self.get_group(group_id)
        updates: dict[str, str] = {}
        if name is not None:
            existing = await self.group_repository.get_by_name(name)
            if existing is not None and existing.id != group_id:
                msg = f"Group '{name}' already exists"
                raise GroupAlreadyExistsError(msg)
            updates["name"] = name
        if description is not None:
            updates["description"] = description
        if updates:
            group = await self.group_repository.update_obj(group, **updates)
        return group

    async def delete_group(self, group_id: str) -> None:
        group = await self.get_group(group_id)
        # Remove all memberships first
        memberships = await self.membership_repository.list_for_group(group_id)
        for m in memberships:
            await self.membership_repository.delete(m)
        await self.group_repository.delete(group)

    # ----- Membership operations -----

    async def add_member(
        self,
        group_id: str,
        subject_id: str,
        *,
        role: GroupRole = GroupRole.MEMBER,
        actor_id: str | None = None,
    ) -> GroupMembership:
        """Add a subject to a group.

        If `actor_id` is given, the actor must be an admin or owner.
        """
        await self.get_group(group_id)

        if actor_id is not None:
            await self._require_admin(group_id, actor_id)

        existing = await self.membership_repository.get(group_id, subject_id)
        if existing is not None:
            return existing

        return await self.membership_repository.create(
            id=self._new_id("mem"),
            group_id=group_id,
            subject_id=subject_id,
            role=role.value,
            joined_at=datetime.now(UTC),
        )

    async def remove_member(
        self,
        group_id: str,
        subject_id: str,
        *,
        actor_id: str | None = None,
    ) -> None:
        """Remove a subject from a group."""
        if actor_id is not None and actor_id != subject_id:
            await self._require_admin(group_id, actor_id)

        membership = await self.membership_repository.get(group_id, subject_id)
        if membership is None:
            msg = f"Subject {subject_id} is not a member of {group_id}"
            raise NotAMemberError(msg)

        # Cannot remove the last owner
        if membership.role == GroupRole.OWNER.value:
            members = await self.membership_repository.list_for_group(group_id)
            owners = [m for m in members if m.role == GroupRole.OWNER.value]
            if len(owners) <= 1:
                msg = "Cannot remove the last owner of a group"
                raise InsufficientPermissionsError(msg)

        await self.membership_repository.delete(membership)

    async def change_role(
        self,
        group_id: str,
        subject_id: str,
        new_role: GroupRole,
        *,
        actor_id: str | None = None,
    ) -> GroupMembership:
        """Change a member's role within a group.

        Only owners can change roles to/from OWNER. Admins can change
        roles among ADMIN and MEMBER.
        """
        if actor_id is not None:
            actor_membership = await self.membership_repository.get(group_id, actor_id)
            if actor_membership is None:
                msg = "Actor is not a member of the group"
                raise InsufficientPermissionsError(msg)

            if (
                new_role == GroupRole.OWNER
                and actor_membership.role != GroupRole.OWNER.value
            ):
                msg = "Only owners can grant ownership"
                raise InsufficientPermissionsError(msg)

        membership = await self.membership_repository.get(group_id, subject_id)
        if membership is None:
            msg = f"Subject {subject_id} is not a member of {group_id}"
            raise NotAMemberError(msg)

        return await self.membership_repository.update_obj(
            membership, role=new_role.value
        )

    async def list_members(self, group_id: str) -> list[GroupMembership]:
        await self.get_group(group_id)
        return await self.membership_repository.list_for_group(group_id)

    async def list_groups_for_subject(self, subject_id: str) -> list[GroupMembership]:
        return await self.membership_repository.list_for_subject(subject_id)

    async def is_member(self, group_id: str, subject_id: str) -> bool:
        membership = await self.membership_repository.get(group_id, subject_id)
        return membership is not None

    async def get_member_role(self, group_id: str, subject_id: str) -> GroupRole | None:
        membership = await self.membership_repository.get(group_id, subject_id)
        if membership is None:
            return None
        return GroupRole(membership.role)

    async def _require_admin(self, group_id: str, subject_id: str) -> None:
        role = await self.get_member_role(group_id, subject_id)
        if role not in (GroupRole.OWNER, GroupRole.ADMIN):
            msg = "Operation requires owner or admin role"
            raise InsufficientPermissionsError(msg)


__all__ = [
    "GroupAlreadyExistsError",
    "GroupError",
    "GroupNotFoundError",
    "GroupService",
    "InsufficientPermissionsError",
    "NotAMemberError",
]
