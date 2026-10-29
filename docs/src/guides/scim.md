# SCIM 2.0

NeoZen implements [SCIM 2.0][scim] (System for Cross-domain Identity Management) for enterprise identity provisioning. This lets external identity providers (Okta, Azure AD, OneLogin, etc.) automatically create, update, and deprovision users in your application.

[scim]: https://datatracker.ietf.org/doc/html/rfc7644

## Quick Start

```python
from neozen.core.scim import SCIMUserService, SCIMGroupService
from neozen.web.scim import (
    UsersEndpoint,
    GroupsEndpoint,
    DiscoveryEndpoints,
)

# Implement adapters that bridge your User/Group models to SCIM
class MyUserAdapter:
    async def create(self, user): ...
    async def get(self, user_id): ...
    async def get_by_username(self, user_name): ...
    async def update(self, user_id, user): ...
    async def delete(self, user_id): ...
    async def list_all(self): ...

# Wire it up
user_service = SCIMUserService(
    adapter=MyUserAdapter(),
    base_url="https://api.example.com/scim/v2",
)

users_endpoint = UsersEndpoint(user_service)
discovery = DiscoveryEndpoints()

# Use in your framework's routes:
#   GET /Users -> users_endpoint.list(query_params)
#   GET /Users/{id} -> users_endpoint.get(id)
#   POST /Users -> users_endpoint.create(json_body)
#   PUT /Users/{id} -> users_endpoint.replace(id, json_body)
#   DELETE /Users/{id} -> users_endpoint.delete(id)
#   GET /ServiceProviderConfig -> discovery.service_provider_config_handler()
```

## Resources

NeoZen ships with the standard SCIM 2.0 User and Group schemas:

```python
from neozen.core.scim import User, Group, Email, Name, GroupMember

user = User(
    user_name="alice",
    display_name="Alice Smith",
    name=Name(given_name="Alice", family_name="Smith"),
    emails=[Email(value="alice@example.com", primary=True)],
    active=True,
)

group = Group(
    display_name="Engineers",
    members=[GroupMember(value="user_1", display="Alice", type="User")],
)
```

## Filtering

NeoZen includes a SCIM filter parser that supports:

| Operator | Meaning | Example |
|----------|---------|---------|
| `eq` | equals (case-insensitive for strings) | `userName eq "alice"` |
| `ne` | not equals | `active ne false` |
| `co` | contains | `userName co "ali"` |
| `sw` | starts with | `userName sw "ali"` |
| `ew` | ends with | `userName ew "ice"` |
| `gt`, `ge`, `lt`, `le` | comparison | `count gt 5` |
| `pr` | present | `displayName pr` |
| `and`, `or`, `not` | logical | `active eq true and userName sw "a"` |

```python
result = await user_service.list_users(
    filter_expr='userName sw "alice" and active eq true',
    start_index=1,
    count=10,
)
```

## Discovery

The discovery endpoints expose:

- `/ServiceProviderConfig` -- features (filter, patch, sort, bulk, ...)
- `/ResourceTypes` -- User and Group resource type descriptors
- `/Schemas` -- attribute schemas for each resource type

```python
from neozen.web.scim import DiscoveryEndpoints, ServiceProviderConfig

config = ServiceProviderConfig(
    patch_supported=False,
    bulk_supported=False,
    filter_supported=True,
    change_password_supported=True,
)
discovery = DiscoveryEndpoints(service_provider_config=config)
```

## Errors

SCIM errors follow [RFC 7644 Section 3.12][scim-errors]:

[scim-errors]: https://datatracker.ietf.org/doc/html/rfc7644#section-3.12

```python
from neozen.core.scim import SCIMNotFoundError, SCIMUniquenessError

try:
    user = await users_endpoint.get("missing")
except SCIMNotFoundError as e:
    body = e.to_response()  # SCIM error JSON
    status = e.status        # 404
```

## Authentication

SCIM endpoints should be protected with OAuth 2.0 bearer token authentication. Use `OAuthTokenService.introspect_access_token` to verify tokens before passing requests to the SCIM endpoints.
