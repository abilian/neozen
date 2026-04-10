"""SCIM discovery endpoints (RFC 7644 Section 4).

Provides:
- /ServiceProviderConfig
- /ResourceTypes
- /Schemas
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from neozen.core.scim.models import SchemaUri


@dataclass
class ServiceProviderConfig:
    """Service Provider Configuration (RFC 7644 Section 5)."""

    documentation_uri: str | None = None
    patch_supported: bool = False
    bulk_supported: bool = False
    bulk_max_operations: int = 0
    bulk_max_payload_size: int = 0
    filter_supported: bool = True
    filter_max_results: int = 200
    change_password_supported: bool = True
    sort_supported: bool = False
    etag_supported: bool = False
    authentication_schemes: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "OAuth 2.0 bearer token authentication",
                "specUri": "https://tools.ietf.org/html/rfc6750",
                "primary": True,
            }
        ]
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemas": [SchemaUri.SERVICE_PROVIDER_CONFIG.value],
            "documentationUri": self.documentation_uri,
            "patch": {"supported": self.patch_supported},
            "bulk": {
                "supported": self.bulk_supported,
                "maxOperations": self.bulk_max_operations,
                "maxPayloadSize": self.bulk_max_payload_size,
            },
            "filter": {
                "supported": self.filter_supported,
                "maxResults": self.filter_max_results,
            },
            "changePassword": {"supported": self.change_password_supported},
            "sort": {"supported": self.sort_supported},
            "etag": {"supported": self.etag_supported},
            "authenticationSchemes": self.authentication_schemes,
        }


@dataclass
class ResourceTypeDescriptor:
    """A SCIM resource type descriptor."""

    id: str  # e.g., "User"
    name: str
    endpoint: str  # e.g., "/Users"
    schema: str
    description: str = ""
    schema_extensions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemas": [SchemaUri.RESOURCE_TYPE.value],
            "id": self.id,
            "name": self.name,
            "endpoint": self.endpoint,
            "description": self.description,
            "schema": self.schema,
            "schemaExtensions": self.schema_extensions,
        }


# Built-in resource type descriptors
USER_RESOURCE_TYPE = ResourceTypeDescriptor(
    id="User",
    name="User",
    endpoint="/Users",
    schema=SchemaUri.USER.value,
    description="User Account",
)

GROUP_RESOURCE_TYPE = ResourceTypeDescriptor(
    id="Group",
    name="Group",
    endpoint="/Groups",
    schema=SchemaUri.GROUP.value,
    description="Group",
)


# Minimal schema descriptors
USER_SCHEMA: dict[str, Any] = {
    "schemas": [SchemaUri.SCHEMA.value],
    "id": SchemaUri.USER.value,
    "name": "User",
    "description": "User Account",
    "attributes": [
        {
            "name": "userName",
            "type": "string",
            "required": True,
            "uniqueness": "server",
            "caseExact": False,
            "mutability": "readWrite",
            "returned": "default",
        },
        {
            "name": "displayName",
            "type": "string",
            "required": False,
            "mutability": "readWrite",
            "returned": "default",
        },
        {
            "name": "active",
            "type": "boolean",
            "required": False,
            "mutability": "readWrite",
            "returned": "default",
        },
        {
            "name": "emails",
            "type": "complex",
            "multiValued": True,
            "required": False,
            "mutability": "readWrite",
            "returned": "default",
        },
    ],
}


GROUP_SCHEMA: dict[str, Any] = {
    "schemas": [SchemaUri.SCHEMA.value],
    "id": SchemaUri.GROUP.value,
    "name": "Group",
    "description": "Group",
    "attributes": [
        {
            "name": "displayName",
            "type": "string",
            "required": True,
            "uniqueness": "server",
            "mutability": "readWrite",
            "returned": "default",
        },
        {
            "name": "members",
            "type": "complex",
            "multiValued": True,
            "required": False,
            "mutability": "readWrite",
            "returned": "default",
        },
    ],
}


class DiscoveryEndpoints:
    """Bundles the three SCIM discovery endpoints.

    Example:
        endpoints = DiscoveryEndpoints(
            service_provider_config=ServiceProviderConfig(),
        )
        # GET /ServiceProviderConfig
        config = await endpoints.service_provider_config_handler()
        # GET /ResourceTypes
        types = await endpoints.resource_types_handler()
        # GET /Schemas
        schemas = await endpoints.schemas_handler()
    """

    def __init__(
        self,
        service_provider_config: ServiceProviderConfig | None = None,
        resource_types: list[ResourceTypeDescriptor] | None = None,
        schemas: list[dict[str, Any]] | None = None,
    ) -> None:
        self.service_provider_config = (
            service_provider_config or ServiceProviderConfig()
        )
        self.resource_types = resource_types or [
            USER_RESOURCE_TYPE,
            GROUP_RESOURCE_TYPE,
        ]
        self.schemas = schemas or [USER_SCHEMA, GROUP_SCHEMA]

    async def service_provider_config_handler(self) -> dict[str, Any]:
        return self.service_provider_config.to_dict()

    async def resource_types_handler(self) -> list[dict[str, Any]]:
        return [rt.to_dict() for rt in self.resource_types]

    async def schemas_handler(self) -> list[dict[str, Any]]:
        return list(self.schemas)


__all__ = [
    "GROUP_RESOURCE_TYPE",
    "GROUP_SCHEMA",
    "USER_RESOURCE_TYPE",
    "USER_SCHEMA",
    "DiscoveryEndpoints",
    "ResourceTypeDescriptor",
    "ServiceProviderConfig",
]
