"""LDAP-backed subject model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from neozen.core.subject import Subject

if TYPE_CHECKING:
    from neozen.storage.ldap.config import LDAPAttributeMap


@dataclass
class LDAPSubject(Subject):
    """A subject backed by an LDAP entry.

    Distinct from `Subject` to carry LDAP-specific fields:
    - dn: the entry's distinguished name (needed for bind authentication)
    - email, username, etc.: extracted from configured LDAP attributes

    LDAP subjects are typically read-only -- modifications go through
    LDAP modify operations, not field assignment.
    """

    id: str = ""
    dn: str = ""
    email: str | None = None
    username: str | None = None
    display_name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    is_active: bool = True
    is_verified: bool = True  # LDAP users are pre-verified
    hashed_password: str | None = None  # Always None for LDAP


def _first_value(entry: Any, attribute: str) -> str | None:
    """Get the first value of a multi-valued LDAP attribute."""
    if not attribute:
        return None
    if not hasattr(entry, attribute):
        return None
    raw = getattr(entry, attribute)
    if raw is None:
        return None
    # ldap3 attributes have a `.values` list
    if hasattr(raw, "values"):
        values = raw.values
        return str(values[0]) if values else None
    if isinstance(raw, list):
        return str(raw[0]) if raw else None
    return str(raw)


def entry_to_subject(entry: Any, attribute_map: LDAPAttributeMap) -> LDAPSubject:
    """Convert an ldap3 entry to an LDAPSubject.

    Falls back gracefully on missing attributes.
    """
    subject_id = (
        _first_value(entry, attribute_map.id)
        or _first_value(entry, attribute_map.username)
        or str(getattr(entry, "entry_dn", "unknown"))
    )

    return LDAPSubject(
        id=subject_id,
        dn=str(getattr(entry, "entry_dn", "")),
        email=_first_value(entry, attribute_map.email),
        username=_first_value(entry, attribute_map.username),
        display_name=_first_value(entry, attribute_map.display_name),
        given_name=_first_value(entry, attribute_map.given_name),
        family_name=_first_value(entry, attribute_map.family_name),
    )


__all__ = [
    "LDAPSubject",
    "entry_to_subject",
]
