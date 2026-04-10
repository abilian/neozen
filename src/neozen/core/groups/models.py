"""Group domain models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from neozen.core.models import NeoZenModel


class GroupRole(StrEnum):
    """Membership role within a group.

    - OWNER: full control of the group, can manage members and delete
    - ADMIN: manage members and group settings
    - MEMBER: regular member, no management rights
    """

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class Group(NeoZenModel):
    """A named collection of subjects.

    Attributes:
        id: Unique identifier
        name: Group name (unique)
        description: Free-form description
        created_at: When the group was created
        created_by: Subject ID of the creator (optional)
    """

    id: str
    name: str
    description: str
    created_at: datetime
    created_by: str | None


class GroupMembership(NeoZenModel):
    """A subject's membership in a group.

    Attributes:
        id: Unique identifier
        group_id: Group ID
        subject_id: Subject ID
        role: Membership role (owner/admin/member)
        joined_at: When the subject joined
    """

    id: str
    group_id: str
    subject_id: str
    role: str  # GroupRole value
    joined_at: datetime


class GroupRepository(Protocol):
    """Repository protocol for groups."""

    async def create(self, **data: Any) -> Group: ...

    async def get_by_id(self, group_id: str) -> Group | None: ...

    async def get_by_name(self, name: str) -> Group | None: ...

    async def list_all(self) -> list[Group]: ...

    async def update_obj(self, obj: Group, **data: Any) -> Group: ...

    async def delete(self, obj: Group) -> None: ...


class GroupMembershipRepository(Protocol):
    """Repository protocol for group memberships."""

    async def create(self, **data: Any) -> GroupMembership: ...

    async def get(self, group_id: str, subject_id: str) -> GroupMembership | None: ...

    async def list_for_group(self, group_id: str) -> list[GroupMembership]: ...

    async def list_for_subject(self, subject_id: str) -> list[GroupMembership]: ...

    async def update_obj(
        self, obj: GroupMembership, **data: Any
    ) -> GroupMembership: ...

    async def delete(self, obj: GroupMembership) -> None: ...


__all__ = [
    "Group",
    "GroupMembership",
    "GroupMembershipRepository",
    "GroupRepository",
    "GroupRole",
]
