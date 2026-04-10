"""Tests for groups, memberships, and invitations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import pytest

from neozen.core.groups.invitations import (
    Invitation,
    InvitationAlreadyUsedError,
    InvitationConfig,
    InvitationExpiredError,
    InvitationNotFoundError,
    InvitationService,
    InvitationStatus,
)
from neozen.core.groups.models import Group, GroupMembership, GroupRole
from neozen.core.groups.service import (
    GroupAlreadyExistsError,
    GroupNotFoundError,
    GroupService,
    InsufficientPermissionsError,
    NotAMemberError,
)

# =============================================================================
# Mock Repositories
# =============================================================================


@dataclass
class MockGroup:
    id: str
    name: str
    description: str
    created_at: datetime
    created_by: str | None


@dataclass
class MockMembership:
    id: str
    group_id: str
    subject_id: str
    role: str
    joined_at: datetime


class MockGroupRepository:
    def __init__(self) -> None:
        self._groups: list[MockGroup] = []

    async def create(self, **data: Any) -> Group:
        group = MockGroup(**data)
        self._groups.append(group)
        return group  # type: ignore[return-value]

    async def get_by_id(self, group_id: str) -> Group | None:
        for g in self._groups:
            if g.id == group_id:
                return g  # type: ignore[return-value]
        return None

    async def get_by_name(self, name: str) -> Group | None:
        for g in self._groups:
            if g.name == name:
                return g  # type: ignore[return-value]
        return None

    async def list_all(self) -> list[Group]:
        return list(self._groups)  # type: ignore[return-value]

    async def update_obj(self, obj: Group, **data: Any) -> Group:
        for k, v in data.items():
            setattr(obj, k, v)
        return obj

    async def delete(self, obj: Group) -> None:
        self._groups.remove(obj)  # type: ignore[arg-type]


class MockMembershipRepository:
    def __init__(self) -> None:
        self._members: list[MockMembership] = []

    async def create(self, **data: Any) -> GroupMembership:
        m = MockMembership(**data)
        self._members.append(m)
        return m  # type: ignore[return-value]

    async def get(self, group_id: str, subject_id: str) -> GroupMembership | None:
        for m in self._members:
            if m.group_id == group_id and m.subject_id == subject_id:
                return m  # type: ignore[return-value]
        return None

    async def list_for_group(self, group_id: str) -> list[GroupMembership]:
        return [m for m in self._members if m.group_id == group_id]  # type: ignore[misc]

    async def list_for_subject(self, subject_id: str) -> list[GroupMembership]:
        return [m for m in self._members if m.subject_id == subject_id]  # type: ignore[misc]

    async def update_obj(self, obj: GroupMembership, **data: Any) -> GroupMembership:
        for k, v in data.items():
            setattr(obj, k, v)
        return obj

    async def delete(self, obj: GroupMembership) -> None:
        self._members.remove(obj)  # type: ignore[arg-type]


@pytest.fixture
def group_service() -> GroupService:
    return GroupService(
        group_repository=MockGroupRepository(),
        membership_repository=MockMembershipRepository(),
    )


# =============================================================================
# Group Service Tests
# =============================================================================


class TestGroupCRUD:
    @pytest.mark.anyio
    async def test_create_group(self, group_service: GroupService) -> None:
        group = await group_service.create_group("engineering")
        assert group.name == "engineering"
        assert group.id.startswith("grp_")

    @pytest.mark.anyio
    async def test_create_group_with_owner(self, group_service: GroupService) -> None:
        group = await group_service.create_group("engineering", owner_id="user_1")
        # Owner should be a member
        assert await group_service.is_member(group.id, "user_1")
        role = await group_service.get_member_role(group.id, "user_1")
        assert role == GroupRole.OWNER

    @pytest.mark.anyio
    async def test_create_duplicate_group(self, group_service: GroupService) -> None:
        await group_service.create_group("engineering")
        with pytest.raises(GroupAlreadyExistsError):
            await group_service.create_group("engineering")

    @pytest.mark.anyio
    async def test_get_group(self, group_service: GroupService) -> None:
        created = await group_service.create_group("engineering")
        fetched = await group_service.get_group(created.id)
        assert fetched.id == created.id

    @pytest.mark.anyio
    async def test_get_nonexistent_group(self, group_service: GroupService) -> None:
        with pytest.raises(GroupNotFoundError):
            await group_service.get_group("nope")

    @pytest.mark.anyio
    async def test_update_group(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng")
        updated = await group_service.update_group(
            group.id, name="engineering", description="The eng team"
        )
        assert updated.name == "engineering"
        assert updated.description == "The eng team"

    @pytest.mark.anyio
    async def test_update_group_name_conflict(
        self, group_service: GroupService
    ) -> None:
        await group_service.create_group("eng")
        other = await group_service.create_group("ops")
        with pytest.raises(GroupAlreadyExistsError):
            await group_service.update_group(other.id, name="eng")

    @pytest.mark.anyio
    async def test_delete_group(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng", owner_id="user_1")
        await group_service.delete_group(group.id)
        with pytest.raises(GroupNotFoundError):
            await group_service.get_group(group.id)
        # Memberships should be removed too
        memberships = await group_service.list_groups_for_subject("user_1")
        assert len(memberships) == 0

    @pytest.mark.anyio
    async def test_list_groups(self, group_service: GroupService) -> None:
        await group_service.create_group("a")
        await group_service.create_group("b")
        groups = await group_service.list_groups()
        assert len(groups) == 2


class TestMembership:
    @pytest.mark.anyio
    async def test_add_member(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng")
        await group_service.add_member(group.id, "user_1")
        assert await group_service.is_member(group.id, "user_1")

    @pytest.mark.anyio
    async def test_add_member_idempotent(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng")
        m1 = await group_service.add_member(group.id, "user_1")
        m2 = await group_service.add_member(group.id, "user_1")
        assert m1.id == m2.id

    @pytest.mark.anyio
    async def test_add_member_requires_admin(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng", owner_id="owner_1")
        await group_service.add_member(group.id, "regular_1", role=GroupRole.MEMBER)

        # Regular member cannot add others
        with pytest.raises(InsufficientPermissionsError):
            await group_service.add_member(group.id, "user_2", actor_id="regular_1")

        # Owner can
        await group_service.add_member(group.id, "user_2", actor_id="owner_1")
        assert await group_service.is_member(group.id, "user_2")

    @pytest.mark.anyio
    async def test_remove_member(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng")
        await group_service.add_member(group.id, "user_1")
        await group_service.remove_member(group.id, "user_1")
        assert not await group_service.is_member(group.id, "user_1")

    @pytest.mark.anyio
    async def test_remove_nonmember(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng")
        with pytest.raises(NotAMemberError):
            await group_service.remove_member(group.id, "ghost")

    @pytest.mark.anyio
    async def test_cannot_remove_last_owner(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng", owner_id="owner_1")
        with pytest.raises(InsufficientPermissionsError):
            await group_service.remove_member(group.id, "owner_1")

    @pytest.mark.anyio
    async def test_can_remove_owner_if_others_exist(
        self, group_service: GroupService
    ) -> None:
        group = await group_service.create_group("eng", owner_id="owner_1")
        await group_service.add_member(group.id, "owner_2", role=GroupRole.OWNER)
        await group_service.remove_member(group.id, "owner_1")
        members = await group_service.list_members(group.id)
        assert len(members) == 1

    @pytest.mark.anyio
    async def test_change_role(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng", owner_id="owner_1")
        await group_service.add_member(group.id, "user_1")
        await group_service.change_role(
            group.id, "user_1", GroupRole.ADMIN, actor_id="owner_1"
        )
        role = await group_service.get_member_role(group.id, "user_1")
        assert role == GroupRole.ADMIN

    @pytest.mark.anyio
    async def test_only_owners_can_grant_ownership(
        self, group_service: GroupService
    ) -> None:
        group = await group_service.create_group("eng", owner_id="owner_1")
        await group_service.add_member(group.id, "admin_1", role=GroupRole.ADMIN)
        await group_service.add_member(group.id, "user_1")

        # Admin cannot grant owner
        with pytest.raises(InsufficientPermissionsError):
            await group_service.change_role(
                group.id, "user_1", GroupRole.OWNER, actor_id="admin_1"
            )

        # Owner can
        await group_service.change_role(
            group.id, "user_1", GroupRole.OWNER, actor_id="owner_1"
        )

    @pytest.mark.anyio
    async def test_list_members(self, group_service: GroupService) -> None:
        group = await group_service.create_group("eng", owner_id="owner_1")
        await group_service.add_member(group.id, "user_1")
        await group_service.add_member(group.id, "user_2")
        members = await group_service.list_members(group.id)
        assert len(members) == 3

    @pytest.mark.anyio
    async def test_list_groups_for_subject(self, group_service: GroupService) -> None:
        eng = await group_service.create_group("eng")
        ops = await group_service.create_group("ops")
        await group_service.add_member(eng.id, "user_1")
        await group_service.add_member(ops.id, "user_1")
        memberships = await group_service.list_groups_for_subject("user_1")
        assert len(memberships) == 2


# =============================================================================
# Invitation Tests
# =============================================================================


@dataclass
class MockInvitation:
    id: str
    token_hash: str
    email: str
    invited_by: str | None
    group_ids_json: str
    role_names_json: str
    message: str
    status: str
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None
    accepted_by: str | None


class MockInvitationRepository:
    def __init__(self) -> None:
        self._items: list[MockInvitation] = []

    async def create(self, **data: Any) -> Invitation:
        inv = MockInvitation(**data)
        self._items.append(inv)
        return inv  # type: ignore[return-value]

    async def get_by_id(self, invitation_id: str) -> Invitation | None:
        for i in self._items:
            if i.id == invitation_id:
                return i  # type: ignore[return-value]
        return None

    async def get_by_hash(self, token_hash: str) -> Invitation | None:
        for i in self._items:
            if i.token_hash == token_hash:
                return i  # type: ignore[return-value]
        return None

    async def list_pending_for_email(self, email: str) -> list[Invitation]:
        return [
            i
            for i in self._items
            if i.email == email and i.status == InvitationStatus.PENDING.value
        ]  # type: ignore[misc]

    async def list_pending(self) -> list[Invitation]:
        return [i for i in self._items if i.status == InvitationStatus.PENDING.value]  # type: ignore[misc]

    async def update_obj(self, obj: Invitation, **data: Any) -> Invitation:
        for k, v in data.items():
            setattr(obj, k, v)
        return obj

    async def delete(self, obj: Invitation) -> None:
        self._items.remove(obj)  # type: ignore[arg-type]


@pytest.fixture
def invitation_service() -> InvitationService:
    return InvitationService(
        config=InvitationConfig(),
        repository=MockInvitationRepository(),
        token_hash_key="test-secret",
    )


class TestInvitations:
    @pytest.mark.anyio
    async def test_create_invitation(
        self, invitation_service: InvitationService
    ) -> None:
        invitation, token = await invitation_service.create_invitation(
            email="user@example.com",
            invited_by="admin_1",
            group_ids=["grp_1", "grp_2"],
            role_names=["user"],
        )
        assert invitation.email == "user@example.com"
        assert invitation.status == InvitationStatus.PENDING.value
        assert token.startswith("nz_inv_")

    @pytest.mark.anyio
    async def test_email_lowercased(
        self, invitation_service: InvitationService
    ) -> None:
        invitation, _ = await invitation_service.create_invitation(
            email="UPPER@Example.COM",
        )
        assert invitation.email == "upper@example.com"

    @pytest.mark.anyio
    async def test_validate_valid_token(
        self, invitation_service: InvitationService
    ) -> None:
        _, token = await invitation_service.create_invitation(email="u@e.com")
        invitation = await invitation_service.validate_token(token)
        assert invitation.status == InvitationStatus.PENDING.value

    @pytest.mark.anyio
    async def test_validate_unknown_token(
        self, invitation_service: InvitationService
    ) -> None:
        with pytest.raises(InvitationNotFoundError):
            await invitation_service.validate_token("nz_inv_bogus")

    @pytest.mark.anyio
    async def test_accept_invitation(
        self, invitation_service: InvitationService
    ) -> None:
        _, token = await invitation_service.create_invitation(
            email="u@e.com",
            group_ids=["grp_1"],
            role_names=["user"],
        )
        details = await invitation_service.accept_invitation(
            token, accepted_by="user_42"
        )
        assert details.email == "u@e.com"
        assert details.group_ids == ["grp_1"]
        assert details.role_names == ["user"]

    @pytest.mark.anyio
    async def test_accept_twice_fails(
        self, invitation_service: InvitationService
    ) -> None:
        _, token = await invitation_service.create_invitation(email="u@e.com")
        await invitation_service.accept_invitation(token, accepted_by="u1")
        with pytest.raises(InvitationAlreadyUsedError):
            await invitation_service.accept_invitation(token, accepted_by="u2")

    @pytest.mark.anyio
    async def test_decline_invitation(
        self, invitation_service: InvitationService
    ) -> None:
        _, token = await invitation_service.create_invitation(email="u@e.com")
        await invitation_service.decline_invitation(token)

        with pytest.raises(InvitationAlreadyUsedError):
            await invitation_service.validate_token(token)

    @pytest.mark.anyio
    async def test_revoke_invitation(
        self, invitation_service: InvitationService
    ) -> None:
        invitation, _ = await invitation_service.create_invitation(email="u@e.com")
        await invitation_service.revoke_invitation(invitation.id)

        retrieved = await invitation_service.repository.get_by_id(invitation.id)
        assert retrieved is not None
        assert retrieved.status == InvitationStatus.REVOKED.value

    @pytest.mark.anyio
    async def test_expired_invitation(self) -> None:
        service = InvitationService(
            config=InvitationConfig(token_lifetime=timedelta(seconds=-1)),
            repository=MockInvitationRepository(),
            token_hash_key="secret",
        )
        _, token = await service.create_invitation(email="u@e.com")

        with pytest.raises(InvitationExpiredError):
            await service.validate_token(token)

    @pytest.mark.anyio
    async def test_list_pending_for_email(
        self, invitation_service: InvitationService
    ) -> None:
        await invitation_service.create_invitation(email="a@e.com")
        await invitation_service.create_invitation(email="a@e.com")
        await invitation_service.create_invitation(email="b@e.com")

        a_invitations = await invitation_service.list_pending_for_email("a@e.com")
        assert len(a_invitations) == 2
