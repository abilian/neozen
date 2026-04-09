# Authorization (RBAC)

NeoZen provides role-based access control with permissions,
scoped role assignments, and policy-based authorization.

## Core Concepts

### Permissions

Permissions use the format `resource:action` or `resource:action:scope`:

```python
from neozen.core.authz.models import Permission

perm = Permission.parse("user:read")
perm = Permission.parse("document:write:own")
wildcard = Permission.parse("*:*")  # superuser

# Check if one permission matches another
assert Permission.parse("user:read").matches(Permission.parse("user:read"))
assert Permission.parse("*:*").matches(Permission.parse("user:read"))
```

### Roles

Roles are named collections of permissions:

```python
from neozen.core.authz.models import Role

admin_role = Role(
    id="role_admin",
    name="admin",
    permissions=frozenset([
        Permission.parse("user:read"),
        Permission.parse("user:write"),
        Permission.parse("role:manage"),
    ]),
    is_system=True,
)

assert admin_role.has_permission(Permission.parse("user:read"))
```

### Built-in Roles

NeoZen provides three system roles:

| Role | Permissions | Description |
|------|-------------|-------------|
| `superuser` | `*:*` | Full access to everything |
| `admin` | `user:*`, `role:*`, `client:*` | Manage users, roles, OAuth clients |
| `user` | `user:read:own`, `user:write:own`, `session:*:own` | Basic authenticated user |

### Role Assignments

Roles can be assigned globally or scoped to a team/resource:

```python
from neozen.core.authz.models import RoleAssignment, ScopeType

# Global assignment
assignment = RoleAssignment(
    id="ra_1",
    subject_id="user_123",
    role_id="role_admin",
    scope_type=ScopeType.GLOBAL,
)

# Team-scoped assignment
assignment = RoleAssignment(
    id="ra_2",
    subject_id="user_456",
    role_id="role_admin",
    scope_type=ScopeType.TEAM,
    scope_id="team_engineering",
)

# Time-limited assignment
from datetime import datetime, timedelta, UTC
assignment = RoleAssignment(
    id="ra_3",
    subject_id="user_789",
    role_id="role_admin",
    scope_type=ScopeType.GLOBAL,
    expires_at=datetime.now(UTC) + timedelta(days=30),
)
```

## Using the Role Service

```python
from neozen.storage.sqlalchemy import RoleServiceFactory

role_service = RoleServiceFactory(session_factory)

# Assign a role
await role_service.assign_role("user_123", "admin")

# Check roles
roles = await get_subject_roles(session_factory, "user_123")
# ["admin", "user"]
```

## Route Protection

### Flask

```python
def require_permission(permission_str):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if not current_user.has_role("admin"):  # simplified check
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/admin/users")
@require_permission("user:read")
def admin_users():
    ...
```

### Litestar

```python
def require_role(role_name: str):
    async def guard(connection, _):
        user = await get_current_user(connection)
        roles = await get_subject_roles(session_factory, user.id)
        if role_name not in roles:
            raise NotAuthorizedException("Insufficient permissions")
    return guard

@get("/admin/users", guards=[login_required(), require_role("admin")])
async def admin_users(request: Request) -> Response:
    ...
```
