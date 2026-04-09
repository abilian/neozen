# Authorization Reference

**Module**: `neozen.core.authz`

## Permission

```python
from neozen.core.authz.models import Permission

perm = Permission.parse("user:read")
perm = Permission.parse("document:write:own")
wildcard = Permission.parse("*:*")
```

| Attribute | Type | Description |
|-----------|------|-------------|
| `resource` | str | Resource type (e.g., `user`, `document`) |
| `action` | str | Action (e.g., `read`, `write`, `delete`) |
| `scope` | str \| None | Optional scope (e.g., `own`, `team`) |

### Methods

| Method | Description |
|--------|-------------|
| `Permission.parse(s)` | Parse `resource:action[:scope]` string |
| `perm.matches(other)` | Check if this permission grants `other` |

Wildcards: `*:*` matches everything. `user:*` matches any user action.

## Role

```python
from neozen.core.authz.models import Role

role = Role(
    id="role_editor",
    name="editor",
    permissions=frozenset([
        Permission.parse("document:read"),
        Permission.parse("document:write"),
    ]),
)
```

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | str | Unique identifier |
| `name` | str | Role name |
| `description` | str | Human-readable description |
| `permissions` | frozenset[Permission] | Granted permissions |
| `is_system` | bool | System role (cannot be deleted) |

### Built-in Roles

| Name | Permissions |
|------|-------------|
| `superuser` | `*:*` |
| `admin` | `user:*`, `role:*`, `client:*` |
| `user` | `user:read:own`, `user:write:own`, `session:*:own` |

## RoleAssignment

```python
from neozen.core.authz.models import RoleAssignment, ScopeType

assignment = RoleAssignment(
    id="ra_1",
    subject_id="user_123",
    role_id="role_admin",
    scope_type=ScopeType.GLOBAL,
    granted_by="user_000",
    expires_at=None,
)
```

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | str | Unique identifier |
| `subject_id` | str | Subject receiving the role |
| `role_id` | str | Role being assigned |
| `scope_type` | ScopeType | GLOBAL, TEAM, or RESOURCE |
| `scope_id` | str \| None | Scope identifier (team/resource ID) |
| `granted_by` | str \| None | Who granted the role |
| `granted_at` | datetime | When granted |
| `expires_at` | datetime \| None | Expiration (None = permanent) |

### ScopeType

| Value | Description |
|-------|-------------|
| `GLOBAL` | Applies everywhere |
| `TEAM` | Scoped to a team |
| `RESOURCE` | Scoped to a specific resource |

## RoleServiceFactory

```python
from neozen.storage.sqlalchemy import RoleServiceFactory, get_subject_roles

role_service = RoleServiceFactory(session_factory)

await role_service.assign_role("user_123", "admin")
await role_service.revoke_role("user_123", "admin")

roles = await get_subject_roles(session_factory, "user_123")
# ["admin", "user"]
```
