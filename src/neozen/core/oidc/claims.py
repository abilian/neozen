"""Claims provider for OIDC.

Maps OAuth scopes to OIDC claims and provides a default implementation
that reads attributes from a subject model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

# Standard OIDC scope-to-claims mapping (OIDC Core 1.0 Section 5.4)
SCOPE_CLAIMS: dict[str, list[str]] = {
    "openid": ["sub"],
    "profile": [
        "name",
        "family_name",
        "given_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
    ],
    "email": ["email", "email_verified"],
    "address": ["address"],
    "phone": ["phone_number", "phone_number_verified"],
}


@dataclass(frozen=True)
class SubjectClaims:
    """Container for claims about a subject.

    This is a normalized intermediate representation -- the claims
    provider returns this, and the ID token / UserInfo endpoint
    serializes a subset based on requested scopes.
    """

    sub: str
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    preferred_username: str | None = None
    picture: str | None = None
    locale: str | None = None
    updated_at: int | None = None
    phone_number: str | None = None
    phone_number_verified: bool | None = None
    address: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


class ClaimsProvider(Protocol):
    """Protocol for providing user claims for OIDC tokens.

    Implementations look up subject attributes by ID and return them
    in a normalized form. The actual scope filtering is done by the
    caller (UserInfo endpoint, ID token generator).
    """

    async def get_claims(
        self,
        subject_id: str,
        scopes: list[str],
    ) -> SubjectClaims | None:
        """Get claims for a subject based on requested scopes.

        Returns None if the subject doesn't exist.
        """
        ...


def filter_claims_by_scopes(
    claims: dict[str, Any],
    scopes: list[str],
) -> dict[str, Any]:
    """Filter a claims dict to only include claims allowed by scopes.

    The `sub` claim is always included.
    """
    allowed: set[str] = {"sub"}
    for scope in scopes:
        allowed.update(SCOPE_CLAIMS.get(scope, []))

    return {k: v for k, v in claims.items() if k in allowed}


class SubjectAttributeLookup(Protocol):
    """Protocol for looking up subject attributes.

    Used by `DefaultClaimsProvider` to read subject data without
    coupling to a specific subject model.
    """

    async def get_subject(self, subject_id: str) -> Any | None:
        """Return the subject object (or None if not found)."""
        ...


class DefaultClaimsProvider:
    """Default `ClaimsProvider` that reads attributes from a subject model.

    Maps subject attributes to claims using `getattr`. The subject
    object can have any of these fields:
        email, email_verified, name, given_name, family_name,
        preferred_username, picture, locale, updated_at,
        phone_number, phone_number_verified, address

    Missing fields are simply omitted from the result.
    """

    def __init__(self, subject_lookup: SubjectAttributeLookup) -> None:
        self.subject_lookup = subject_lookup

    async def get_claims(
        self,
        subject_id: str,
        scopes: list[str],
    ) -> SubjectClaims | None:
        subject = await self.subject_lookup.get_subject(subject_id)
        if subject is None:
            return None

        # Extract whatever attributes the subject model exposes.
        # `username` is a fallback for `preferred_username`.
        return SubjectClaims(
            sub=subject_id,
            email=getattr(subject, "email", None),
            email_verified=getattr(subject, "is_verified", None),
            name=getattr(subject, "name", None),
            given_name=getattr(subject, "given_name", None),
            family_name=getattr(subject, "family_name", None),
            preferred_username=getattr(subject, "preferred_username", None)
            or getattr(subject, "username", None),
            picture=getattr(subject, "picture", None),
            locale=getattr(subject, "locale", None),
            phone_number=getattr(subject, "phone_number", None),
            phone_number_verified=getattr(subject, "phone_number_verified", None),
            address=getattr(subject, "address", None),
        )


__all__ = [
    "SCOPE_CLAIMS",
    "ClaimsProvider",
    "DefaultClaimsProvider",
    "SubjectAttributeLookup",
    "SubjectClaims",
    "filter_claims_by_scopes",
]
