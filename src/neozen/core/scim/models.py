"""SCIM 2.0 resource models (RFC 7643)."""

from __future__ import annotations

import typing
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar

from neozen.core.scim.errors import SCIMValidationError


class SchemaUri(StrEnum):
    """Standard SCIM 2.0 schema URIs."""

    USER = "urn:ietf:params:scim:schemas:core:2.0:User"
    GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
    ENTERPRISE_USER = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
    PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    SERVICE_PROVIDER_CONFIG = (
        "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
    )
    RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
    SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"


def _to_iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _omit_none(d: dict[str, Any]) -> dict[str, Any]:
    """Recursively omit None and empty list values."""
    result: dict[str, Any] = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, list) and not v:
            continue
        if isinstance(v, dict):
            cleaned = _omit_none(v)
            if cleaned:
                result[k] = cleaned
        else:
            result[k] = v
    return result


def _boolean(value: object) -> bool:
    """A SCIM boolean; some identity providers send "True" or "false"."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    msg = f"not a boolean: {value!r}"
    raise ValueError(msg)


def parse_resource[R](from_dict: Callable[[dict[str, Any]], R], payload: object) -> R:
    """A resource from a request body; anything malformed is a 400.

    Raises:
        SCIMValidationError: The body isn't an object, misses a required
            attribute, or has a value of the wrong type.
    """
    if not isinstance(payload, dict):
        msg = "Request body must be a JSON object"
        raise SCIMValidationError(msg)
    try:
        return from_dict(typing.cast("dict[str, Any]", payload))  # a JSON object
    except KeyError as e:
        msg = f"Missing required field: {e}"
        raise SCIMValidationError(msg) from e
    except (TypeError, AttributeError, ValueError) as e:
        msg = f"Invalid value: {e}"
        raise SCIMValidationError(msg) from e


@dataclass
class Meta:
    """SCIM resource metadata (RFC 7643 Section 3.1)."""

    resource_type: str
    created: datetime | None = None
    last_modified: datetime | None = None
    location: str | None = None
    version: str | None = None  # ETag

    def to_dict(self) -> dict[str, Any]:
        return _omit_none({
            "resourceType": self.resource_type,
            "created": _to_iso(self.created),
            "lastModified": _to_iso(self.last_modified),
            "location": self.location,
            "version": self.version,
        })


@dataclass
class Name:
    """A user's name (RFC 7643 Section 4.1.1)."""

    formatted: str | None = None
    family_name: str | None = None
    given_name: str | None = None
    middle_name: str | None = None
    honorific_prefix: str | None = None
    honorific_suffix: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _omit_none({
            "formatted": self.formatted,
            "familyName": self.family_name,
            "givenName": self.given_name,
            "middleName": self.middle_name,
            "honorificPrefix": self.honorific_prefix,
            "honorificSuffix": self.honorific_suffix,
        })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Name:
        return cls(
            formatted=data.get("formatted"),
            family_name=data.get("familyName"),
            given_name=data.get("givenName"),
            middle_name=data.get("middleName"),
            honorific_prefix=data.get("honorificPrefix"),
            honorific_suffix=data.get("honorificSuffix"),
        )


@dataclass
class Email:
    """An email address (RFC 7643 Section 4.1.2)."""

    value: str
    type: str | None = None  # "work", "home", "other"
    primary: bool = False
    display: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _omit_none({
            "value": self.value,
            "type": self.type,
            "primary": self.primary or None,
            "display": self.display,
        })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Email:
        return cls(
            value=data["value"],
            type=data.get("type"),
            primary=bool(data.get("primary")),
            display=data.get("display"),
        )


@dataclass
class PhoneNumber:
    """A phone number."""

    value: str
    type: str | None = None  # "work", "home", "mobile", "fax", "pager", "other"
    primary: bool = False

    def to_dict(self) -> dict[str, Any]:
        return _omit_none({
            "value": self.value,
            "type": self.type,
            "primary": self.primary or None,
        })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PhoneNumber:
        return cls(
            value=data["value"],
            type=data.get("type"),
            primary=bool(data.get("primary")),
        )


@dataclass
class GroupMember:
    """A member of a group (RFC 7643 Section 4.2)."""

    value: str  # subject ID
    display: str | None = None
    type: str | None = None  # "User" or "Group"
    ref: str | None = None  # $ref

    def to_dict(self) -> dict[str, Any]:
        return _omit_none({
            "value": self.value,
            "display": self.display,
            "type": self.type,
            "$ref": self.ref,
        })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GroupMember:
        return cls(
            value=data["value"],
            display=data.get("display"),
            type=data.get("type"),
            ref=data.get("$ref"),
        )


@dataclass
class SCIMResource:
    """Base class for SCIM resources."""

    schemas: ClassVar[list[str]] = []

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError


@dataclass
class User(SCIMResource):
    """SCIM User resource (RFC 7643 Section 4.1)."""

    schemas: ClassVar[list[str]] = [SchemaUri.USER.value]

    user_name: str = ""
    id: str | None = None
    external_id: str | None = None
    name: Name | None = None
    display_name: str | None = None
    nick_name: str | None = None
    profile_url: str | None = None
    title: str | None = None
    user_type: str | None = None
    preferred_language: str | None = None
    locale: str | None = None
    timezone: str | None = None
    active: bool = True
    password: str | None = None  # Write-only; never returned
    emails: list[Email] = field(default_factory=list)
    phone_numbers: list[PhoneNumber] = field(default_factory=list)
    meta: Meta | None = None

    def to_dict(self) -> dict[str, Any]:
        return _omit_none({
            "schemas": self.schemas,
            "id": self.id,
            "externalId": self.external_id,
            "userName": self.user_name,
            "name": self.name.to_dict() if self.name else None,
            "displayName": self.display_name,
            "nickName": self.nick_name,
            "profileUrl": self.profile_url,
            "title": self.title,
            "userType": self.user_type,
            "preferredLanguage": self.preferred_language,
            "locale": self.locale,
            "timezone": self.timezone,
            "active": self.active,
            "emails": [e.to_dict() for e in self.emails] if self.emails else None,
            "phoneNumbers": (
                [p.to_dict() for p in self.phone_numbers]
                if self.phone_numbers
                else None
            ),
            "meta": self.meta.to_dict() if self.meta else None,
        })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> User:
        return cls(
            id=data.get("id"),
            external_id=data.get("externalId"),
            user_name=data.get("userName", ""),
            name=Name.from_dict(data["name"]) if data.get("name") else None,
            display_name=data.get("displayName"),
            nick_name=data.get("nickName"),
            profile_url=data.get("profileUrl"),
            title=data.get("title"),
            user_type=data.get("userType"),
            preferred_language=data.get("preferredLanguage"),
            locale=data.get("locale"),
            timezone=data.get("timezone"),
            active=_boolean(data.get("active", True)),
            password=data.get("password"),
            emails=[Email.from_dict(e) for e in data.get("emails", [])],
            phone_numbers=[
                PhoneNumber.from_dict(p) for p in data.get("phoneNumbers", [])
            ],
        )

    def primary_email(self) -> str | None:
        """Return the primary email value, or the first if none is primary."""
        if not self.emails:
            return None
        for e in self.emails:
            if e.primary:
                return e.value
        return self.emails[0].value


@dataclass
class Group(SCIMResource):
    """SCIM Group resource (RFC 7643 Section 4.2)."""

    schemas: ClassVar[list[str]] = [SchemaUri.GROUP.value]

    display_name: str = ""
    id: str | None = None
    external_id: str | None = None
    members: list[GroupMember] = field(default_factory=list)
    meta: Meta | None = None

    def to_dict(self) -> dict[str, Any]:
        return _omit_none({
            "schemas": self.schemas,
            "id": self.id,
            "externalId": self.external_id,
            "displayName": self.display_name,
            "members": ([m.to_dict() for m in self.members] if self.members else None),
            "meta": self.meta.to_dict() if self.meta else None,
        })

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Group:
        return cls(
            id=data.get("id"),
            external_id=data.get("externalId"),
            display_name=data.get("displayName", ""),
            members=[GroupMember.from_dict(m) for m in data.get("members", [])],
        )


@dataclass
class ListResponse:
    """SCIM ListResponse (RFC 7644 Section 3.4.2)."""

    resources: Sequence[SCIMResource]
    total_results: int
    start_index: int = 1
    items_per_page: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemas": [SchemaUri.LIST_RESPONSE.value],
            "totalResults": self.total_results,
            "startIndex": self.start_index,
            "itemsPerPage": self.items_per_page or len(self.resources),
            "Resources": [r.to_dict() for r in self.resources],
        }


__all__ = [
    "Email",
    "Group",
    "GroupMember",
    "ListResponse",
    "Meta",
    "Name",
    "PhoneNumber",
    "SCIMResource",
    "SchemaUri",
    "User",
]
