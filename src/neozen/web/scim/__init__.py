"""HTTP adapters for SCIM 2.0 endpoints.

These adapters are framework-agnostic. The framework integration
layer is responsible for:
- Routing HTTP methods (GET/POST/PUT/PATCH/DELETE) to the right
  handler method
- Authentication (typically OAuth bearer tokens)
- Parsing JSON bodies and query parameters
- Returning JSON responses with `application/scim+json` content type
"""

from __future__ import annotations

from neozen.web.scim.discovery import (
    DiscoveryEndpoints,
    ResourceTypeDescriptor,
    ServiceProviderConfig,
)
from neozen.web.scim.groups_endpoint import GroupsEndpoint
from neozen.web.scim.users_endpoint import UsersEndpoint

__all__ = [
    "DiscoveryEndpoints",
    "GroupsEndpoint",
    "ResourceTypeDescriptor",
    "ServiceProviderConfig",
    "UsersEndpoint",
]
