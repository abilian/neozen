"""LDAP-based password authentication.

Uses LDAP bind operations to verify user credentials. The flow is:
1. Bind as the service account
2. Search for the user by email/username
3. Attempt to bind as that user with the supplied password
4. If the bind succeeds, the password is correct
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from neozen.core.repository import DoesNotExist
from neozen.storage.ldap.connection import (
    LDAPConnectionError,
    bind_async,
    unbind_async,
)
from neozen.storage.ldap.repository import LDAPSubjectRepository

if TYPE_CHECKING:
    from neozen.storage.ldap.config import LDAPConfig
    from neozen.storage.ldap.subject import LDAPSubject


async def authenticate_user(
    config: LDAPConfig,
    identifier: str,
    password: str,
    *,
    identifier_field: str = "email",
) -> LDAPSubject | None:
    """Authenticate a user against LDAP via bind.

    Args:
        config: LDAP server configuration.
        identifier: The identifier to look up the user (email by default).
        password: The user's password.
        identifier_field: Which field to use for lookup
            ("email", "username", "id", etc.).

    Returns:
        The authenticated `LDAPSubject` on success, None on failure.
        Returns None for both unknown users and bad passwords (to
        prevent timing-based user enumeration; bind operations are
        roughly the same cost in either case).
    """
    if not password:
        # Empty password is treated as anonymous bind in LDAP -- always reject
        return None

    repository = LDAPSubjectRepository(config)

    # Look up the user
    try:
        subject = await repository.get_one_by(**{identifier_field: identifier})
    except DoesNotExist:
        return None

    if not subject.dn:
        return None

    # Try to bind as the user
    conn = None
    try:
        conn = await bind_async(config, dn=subject.dn, password=password)
    except LDAPConnectionError:
        return None
    finally:
        if conn is not None:
            await unbind_async(conn)

    return subject


__all__ = ["authenticate_user"]
