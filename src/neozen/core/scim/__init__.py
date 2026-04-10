"""SCIM 2.0 implementation for NeoZen.

System for Cross-domain Identity Management (RFC 7643/7644).
Provides identity resources (User, Group), filtering, and CRUD
operations for external identity provisioning.

Currently supported:
- User and Group resources with core schema
- Basic filter parsing (eq, ne, co, sw, ew, pr, gt, ge, lt, le, and, or, not)
- Pagination (startIndex, count)
- Service layer with adapter protocols
- Discovery: ServiceProviderConfig, ResourceTypes, Schemas

See `neozen.web.scim` for HTTP endpoints.
"""

from __future__ import annotations

from neozen.core.scim.errors import (
    SCIMError,
    SCIMFilterError,
    SCIMNotFoundError,
    SCIMUniquenessError,
)
from neozen.core.scim.filter_parser import (
    Conjunction,
    FilterExpression,
    FilterOp,
    Negation,
    SimpleExpression,
    parse_filter,
)
from neozen.core.scim.models import (
    Email,
    Group,
    GroupMember,
    ListResponse,
    Meta,
    Name,
    PhoneNumber,
    SchemaUri,
    SCIMResource,
    User,
)
from neozen.core.scim.service import (
    GroupAdapter,
    SCIMGroupService,
    SCIMUserService,
    SubjectAdapter,
)

__all__ = [
    "Conjunction",
    "Email",
    "FilterExpression",
    "FilterOp",
    "Group",
    "GroupAdapter",
    "GroupMember",
    "ListResponse",
    "Meta",
    "Name",
    "Negation",
    "PhoneNumber",
    "SCIMError",
    "SCIMFilterError",
    "SCIMGroupService",
    "SCIMNotFoundError",
    "SCIMResource",
    "SCIMUniquenessError",
    "SCIMUserService",
    "SchemaUri",
    "SimpleExpression",
    "SubjectAdapter",
    "User",
    "parse_filter",
]
