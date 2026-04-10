"""Group management for NeoZen.

Provides groups (collections of subjects), group memberships, and an
invitation system with token-based acceptance.

Groups are distinct from roles:
- Roles grant permissions
- Groups organize subjects (departments, teams, projects)
- A group can have an associated role applied to all members
"""

from __future__ import annotations

from neozen.core.groups.invitations import (
    Invitation,
    InvitationConfig,
    InvitationRepository,
    InvitationService,
    InvitationStatus,
)
from neozen.core.groups.models import (
    Group,
    GroupMembership,
    GroupMembershipRepository,
    GroupRepository,
    GroupRole,
)
from neozen.core.groups.service import GroupService

__all__ = [
    "Group",
    "GroupMembership",
    "GroupMembershipRepository",
    "GroupRepository",
    "GroupRole",
    "GroupService",
    "Invitation",
    "InvitationConfig",
    "InvitationRepository",
    "InvitationService",
    "InvitationStatus",
]
