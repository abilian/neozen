"""LDAP storage backend for NeoZen.

Provides a read-mostly LDAP backend that maps directory entries to
Subject objects. Uses ldap3 (pure Python, no C dependencies).

Install with: `uv add "neozen[ldap]"`

Example:
    config = LDAPConfig(
        url="ldap://ldap.example.com",
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="secret",
        base_dn="ou=people,dc=example,dc=com",
        user_filter="(objectClass=inetOrgPerson)",
    )
    repository = LDAPSubjectRepository(config)

    # Find a user by email
    user = await repository.get_one_by(email="alice@example.com")

    # Authenticate (bind as the user)
    valid = await authenticate_user(config, "alice@example.com", "password")
"""

from __future__ import annotations

from neozen.storage.ldap.auth import authenticate_user
from neozen.storage.ldap.config import LDAPAttributeMap, LDAPConfig
from neozen.storage.ldap.connection import LDAPConnectionError
from neozen.storage.ldap.repository import LDAPSubjectRepository
from neozen.storage.ldap.subject import LDAPSubject

__all__ = [
    "LDAPAttributeMap",
    "LDAPConfig",
    "LDAPConnectionError",
    "LDAPSubject",
    "LDAPSubjectRepository",
    "authenticate_user",
]
