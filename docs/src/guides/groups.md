# Groups & Invitations

NeoZen provides a group management system distinct from RBAC roles:

- **Roles** grant permissions
- **Groups** organize subjects (departments, teams, projects)

## Groups

```python
from neozen.core.groups import GroupService, GroupRole

service = GroupService(
    group_repository=group_repo,
    membership_repository=membership_repo,
)

# Create a group with the creator as owner
group = await service.create_group(
    name="engineering",
    description="Engineering team",
    owner_id="user_123",
)

# Add members
await service.add_member(
    group.id,
    "user_456",
    role=GroupRole.MEMBER,
    actor_id="user_123",  # must be admin/owner
)

# Change role (only owners can grant ownership)
await service.change_role(
    group.id,
    "user_456",
    GroupRole.ADMIN,
    actor_id="user_123",
)

# List members
members = await service.list_members(group.id)

# List a subject's groups
my_groups = await service.list_groups_for_subject("user_456")

# Remove (last owner cannot be removed)
await service.remove_member(group.id, "user_456")
```

## Membership Roles

| Role | Capabilities |
|------|--------------|
| **owner** | Full control: manage members, change roles (including ownership), delete the group |
| **admin** | Manage members, change roles (except ownership) |
| **member** | Regular member, no management rights |

## Permission Rules

- Adding/removing members and changing roles requires admin or owner
- Only owners can grant or revoke ownership
- The last owner of a group cannot be removed
- Subjects can always remove themselves

## Invitations

The invitation system lets admins invite users via email with pre-assigned groups and roles:

```python
from neozen.core.groups import InvitationConfig, InvitationService

service = InvitationService(
    config=InvitationConfig(
        accept_url_template="https://app.example.com/invite?token={token}",
    ),
    repository=invitation_repo,
    token_hash_key="secret",
)

# Create invitation
invitation, token = await service.create_invitation(
    email="newuser@example.com",
    invited_by="admin_1",
    group_ids=["grp_engineering"],
    role_names=["user"],
    message="Welcome to the team!",
)

# Send the email (use NotificationService or similar)
url = f"https://app.example.com/invite?token={token}"
# email_sender.send(...)

# Later: user clicks the link
details = await service.accept_invitation(token, accepted_by=new_user_id)
# details.email, details.group_ids, details.role_names
# Now apply the group memberships and role assignments
```

## Invitation Lifecycle

| Status | Description |
|--------|-------------|
| `pending` | Created, not yet acted upon |
| `accepted` | Successfully accepted |
| `declined` | Explicitly declined by recipient |
| `expired` | Token lifetime exceeded |
| `revoked` | Cancelled by an admin |

## Security

- Tokens use the standard NeoZen format with HMAC-SHA256 hashing
- Only the hash is stored in the database
- Single-use: accepting marks the invitation as `accepted`
- Default lifetime: 7 days
- Email addresses are lowercased for case-insensitive matching
