"""LDAP-backed subject repository.

Implements `ReadableRepositoryProtocol` (read-only).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from neozen.core.repository import DoesNotExist
from neozen.storage.ldap.connection import (
    bind_async,
    search_async,
    unbind_async,
)
from neozen.storage.ldap.subject import LDAPSubject, entry_to_subject

if TYPE_CHECKING:
    from neozen.storage.ldap.config import LDAPConfig


class LDAPSubjectRepository:
    """Read-only LDAP repository for Subject lookups.

    Implements `ReadableRepositoryProtocol[LDAPSubject]`. Supports
    lookups by id, email, username, etc., as well as listing.

    Write operations (create/update/delete) raise NotImplementedError;
    LDAP write support is left to consuming applications that have
    specific schema requirements.

    Each operation opens a fresh bound connection. For high-throughput
    use, wrap this in a connection-pooling layer.

    Example:
        config = LDAPConfig(
            url="ldap://ldap.example.com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            base_dn="ou=people,dc=example,dc=com",
        )
        repo = LDAPSubjectRepository(config)

        user = await repo.get_one_by(email="alice@example.com")
        assert user.email == "alice@example.com"
    """

    model_type: type[LDAPSubject] = LDAPSubject

    def __init__(self, config: LDAPConfig) -> None:
        self.config = config

    def _build_filter(self, filters: dict[str, Any]) -> str:
        """Convert filter kwargs into an LDAP search filter string.

        Maps NeoZen field names (id, email, username, ...) to LDAP
        attribute names via the configured attribute map.
        """
        attr_map = self.config.attribute_map
        field_to_attr = {
            "id": attr_map.id,
            "email": attr_map.email,
            "username": attr_map.username,
            "display_name": attr_map.display_name,
            "given_name": attr_map.given_name,
            "family_name": attr_map.family_name,
        }

        clauses: list[str] = []
        for field_name, value in filters.items():
            ldap_attr = field_to_attr.get(field_name, field_name)
            escaped = self._escape(str(value))
            clauses.append(f"({ldap_attr}={escaped})")

        # Combine with the configured user_filter via &
        all_clauses: list[str] = []
        if self.config.user_filter:
            all_clauses.append(self.config.user_filter)
        all_clauses.extend(clauses)

        if not all_clauses:
            return "(objectClass=*)"
        if len(all_clauses) == 1:
            return all_clauses[0]
        return "(&" + "".join(all_clauses) + ")"

    @staticmethod
    def _escape(value: str) -> str:
        """Escape special characters in an LDAP filter value (RFC 4515)."""
        replacements = {
            "\\": r"\5c",
            "*": r"\2a",
            "(": r"\28",
            ")": r"\29",
            "\x00": r"\00",
        }
        result = value
        for char, escape in replacements.items():
            result = result.replace(char, escape)
        return result

    async def _search(
        self,
        filters: dict[str, Any],
        size_limit: int = 1000,
    ) -> list[LDAPSubject]:
        search_filter = self._build_filter(filters)
        conn = await bind_async(self.config)
        try:
            entries = await search_async(
                conn,
                base_dn=self.config.base_dn,
                search_filter=search_filter,
                attributes=self.config.attribute_map.attribute_list(),
                size_limit=size_limit,
            )
        finally:
            await unbind_async(conn)

        return [entry_to_subject(entry, self.config.attribute_map) for entry in entries]

    async def get_one_by(self, **filters: Any) -> LDAPSubject:
        """Get a single subject by filter. Raises DoesNotExist if not found."""
        results = await self._search(filters, size_limit=2)
        if not results:
            raise DoesNotExist
        return results[0]

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: Any,
    ) -> list[LDAPSubject]:
        """Get multiple subjects by filter."""
        size_limit = (offset + limit) if limit else 1000
        results = await self._search(filters, size_limit=size_limit)
        if limit is not None:
            return results[offset : offset + limit]
        return results[offset:]

    async def count(self, **filters: Any) -> int:
        """Count matching subjects.

        Note: this issues a full search and counts the results, which
        may be slow for large directories.
        """
        results = await self._search(filters)
        return len(results)

    async def exists(self, **filters: Any) -> bool:
        """Check whether at least one subject matches the filter."""
        results = await self._search(filters, size_limit=1)
        return len(results) > 0

    # Write operations are not supported for the read-only LDAP backend.
    # Consumers that need write support should subclass and implement.

    async def create(self, **data: Any) -> LDAPSubject:
        msg = (
            "LDAPSubjectRepository is read-only. Subclass and override "
            "create() to add write support."
        )
        raise NotImplementedError(msg)

    async def update_obj(self, obj: LDAPSubject, **data: Any) -> LDAPSubject:
        msg = (
            "LDAPSubjectRepository is read-only. Subclass and override "
            "update_obj() to add write support."
        )
        raise NotImplementedError(msg)

    async def delete(self, obj: LDAPSubject) -> None:
        msg = (
            "LDAPSubjectRepository is read-only. Subclass and override "
            "delete() to add write support."
        )
        raise NotImplementedError(msg)


__all__ = ["LDAPSubjectRepository"]
