"""Integration tests for the LDAP backend.

Uses ldap3's MOCK_SYNC strategy to simulate an LDAP server in-memory,
so these tests run without external dependencies.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_SLAPD_2_4, Connection, Server

from neozen.core.repository import DoesNotExist
from neozen.storage.ldap import (
    LDAPAttributeMap,
    LDAPConfig,
    LDAPSubjectRepository,
    authenticate_user,
)
from neozen.storage.ldap.connection import LDAPConnectionError

# =============================================================================
# Mock LDAP Server Setup
# =============================================================================


def _populate_mock_server(server: Server) -> None:
    """Add some test entries to a mock ldap3 server."""
    conn = Connection(
        server,
        user="cn=admin,dc=example,dc=com",
        password="adminpass",
        client_strategy=MOCK_SYNC,
    )
    conn.bind()

    # Service account (admin)
    conn.strategy.add_entry(
        "cn=admin,dc=example,dc=com",
        {
            "objectClass": ["inetOrgPerson", "person", "top"],
            "cn": ["admin"],
            "sn": ["Admin"],
            "userPassword": "adminpass",
        },
    )

    # Test users
    conn.strategy.add_entry(
        "uid=alice,ou=people,dc=example,dc=com",
        {
            "objectClass": ["inetOrgPerson", "person", "top"],
            "uid": ["alice"],
            "cn": ["Alice Smith"],
            "sn": ["Smith"],
            "givenName": ["Alice"],
            "displayName": ["Alice Smith"],
            "mail": ["alice@example.com"],
            "userPassword": "alicepass",
        },
    )
    conn.strategy.add_entry(
        "uid=bob,ou=people,dc=example,dc=com",
        {
            "objectClass": ["inetOrgPerson", "person", "top"],
            "uid": ["bob"],
            "cn": ["Bob Jones"],
            "sn": ["Jones"],
            "givenName": ["Bob"],
            "displayName": ["Bob Jones"],
            "mail": ["bob@example.com"],
            "userPassword": "bobpass",
        },
    )
    conn.strategy.add_entry(
        "uid=carol,ou=people,dc=example,dc=com",
        {
            "objectClass": ["inetOrgPerson", "person", "top"],
            "uid": ["carol"],
            "cn": ["Carol White"],
            "sn": ["White"],
            "givenName": ["Carol"],
            "displayName": ["Carol White"],
            "mail": ["carol@example.com"],
            "userPassword": "carolpass",
        },
    )
    conn.unbind()


@pytest.fixture
def mock_server() -> Generator[Server, None, None]:
    """Create a mock ldap3 server pre-populated with test data."""
    server = Server("ldap.test", get_info=OFFLINE_SLAPD_2_4)
    _populate_mock_server(server)
    return server


def _make_mock_factories(mock_server: Server) -> tuple[Any, Any, Any]:
    """Build the three patched async helpers for a given mock server."""
    from ldap3 import SUBTREE
    from ldap3.core.exceptions import LDAPException

    def _make_conn(
        dn: str | None = None,
        password: str | None = None,
    ) -> Connection:
        try:
            conn = Connection(
                mock_server,
                user=dn or "cn=admin,dc=example,dc=com",
                password=password or "adminpass",
                client_strategy=MOCK_SYNC,
            )
            if not conn.bind():
                msg = "bind failed"
                raise LDAPConnectionError(msg)
        except LDAPException as e:
            msg = f"LDAP bind failed: {e}"
            raise LDAPConnectionError(msg) from e
        return conn

    async def patched_bind_async(  # noqa: RUF029
        config: LDAPConfig,
        *,
        dn: str | None = None,
        password: str | None = None,
    ) -> Connection:
        actual_dn = dn if dn is not None else config.bind_dn
        actual_password = password if password is not None else config.bind_password
        return _make_conn(actual_dn, actual_password)

    async def patched_search_async(  # noqa: RUF029
        conn: Connection,
        *,
        base_dn: str,
        search_filter: str,
        attributes: list[str],
        size_limit: int = 1000,
    ) -> list[Any]:
        try:
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                size_limit=size_limit,
            )
        except LDAPException as e:
            msg = f"LDAP search failed: {e}"
            raise LDAPConnectionError(msg) from e
        return list(conn.entries)

    async def patched_unbind_async(conn: Connection | None) -> None:  # noqa: RUF029
        if conn is not None:
            conn.unbind()

    return patched_bind_async, patched_search_async, patched_unbind_async


@pytest.fixture
def ldap_config(mock_server: Server, monkeypatch: pytest.MonkeyPatch) -> LDAPConfig:
    """Patch the LDAP connection helpers to use the mock server."""
    from neozen.storage.ldap import (
        auth as auth_module,
        connection as conn_module,
        repository as repo_module,
    )

    bind_fn, search_fn, unbind_fn = _make_mock_factories(mock_server)

    for module in (conn_module, repo_module, auth_module):
        if hasattr(module, "bind_async"):
            monkeypatch.setattr(module, "bind_async", bind_fn)
        if hasattr(module, "search_async"):
            monkeypatch.setattr(module, "search_async", search_fn)
        if hasattr(module, "unbind_async"):
            monkeypatch.setattr(module, "unbind_async", unbind_fn)

    return LDAPConfig(
        url="ldap://ldap.test",
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="adminpass",
        base_dn="ou=people,dc=example,dc=com",
        user_filter="(objectClass=inetOrgPerson)",
    )


# =============================================================================
# Repository Tests
# =============================================================================


@pytest.fixture
def repository(ldap_config: LDAPConfig) -> LDAPSubjectRepository:
    return LDAPSubjectRepository(ldap_config)


class TestLDAPSubjectRepository:
    @pytest.mark.anyio
    async def test_get_by_email(self, repository: LDAPSubjectRepository) -> None:
        user = await repository.get_one_by(email="alice@example.com")
        assert user.email == "alice@example.com"
        assert user.username == "alice"
        assert user.given_name == "Alice"
        assert user.family_name == "Smith"
        assert user.display_name == "Alice Smith"
        assert user.dn == "uid=alice,ou=people,dc=example,dc=com"

    @pytest.mark.anyio
    async def test_get_by_username(self, repository: LDAPSubjectRepository) -> None:
        user = await repository.get_one_by(username="bob")
        assert user.email == "bob@example.com"

    @pytest.mark.anyio
    async def test_get_by_id(self, repository: LDAPSubjectRepository) -> None:
        user = await repository.get_one_by(id="carol")
        assert user.email == "carol@example.com"

    @pytest.mark.anyio
    async def test_get_unknown_raises(self, repository: LDAPSubjectRepository) -> None:
        with pytest.raises(DoesNotExist):
            await repository.get_one_by(email="ghost@example.com")

    @pytest.mark.anyio
    async def test_get_many_by_no_filter(
        self, repository: LDAPSubjectRepository
    ) -> None:
        users = await repository.get_many_by()
        emails = sorted(u.email for u in users if u.email)
        assert "alice@example.com" in emails
        assert "bob@example.com" in emails
        assert "carol@example.com" in emails

    @pytest.mark.anyio
    async def test_get_many_with_filter(
        self, repository: LDAPSubjectRepository
    ) -> None:
        users = await repository.get_many_by(username="alice")
        assert len(users) == 1
        assert users[0].email == "alice@example.com"

    @pytest.mark.anyio
    async def test_get_many_with_pagination(
        self, repository: LDAPSubjectRepository
    ) -> None:
        users = await repository.get_many_by(offset=0, limit=2)
        assert len(users) == 2

    @pytest.mark.anyio
    async def test_count(self, repository: LDAPSubjectRepository) -> None:
        count = await repository.count()
        assert count >= 3

    @pytest.mark.anyio
    async def test_count_with_filter(self, repository: LDAPSubjectRepository) -> None:
        count = await repository.count(username="alice")
        assert count == 1

    @pytest.mark.anyio
    async def test_exists_true(self, repository: LDAPSubjectRepository) -> None:
        assert await repository.exists(email="alice@example.com")

    @pytest.mark.anyio
    async def test_exists_false(self, repository: LDAPSubjectRepository) -> None:
        assert not await repository.exists(email="ghost@example.com")

    @pytest.mark.anyio
    async def test_create_raises(self, repository: LDAPSubjectRepository) -> None:
        with pytest.raises(NotImplementedError):
            await repository.create(email="x@example.com")

    @pytest.mark.anyio
    async def test_update_raises(self, repository: LDAPSubjectRepository) -> None:
        from neozen.storage.ldap.subject import LDAPSubject

        with pytest.raises(NotImplementedError):
            await repository.update_obj(LDAPSubject(id="x"), email="y@e.com")

    @pytest.mark.anyio
    async def test_delete_raises(self, repository: LDAPSubjectRepository) -> None:
        from neozen.storage.ldap.subject import LDAPSubject

        with pytest.raises(NotImplementedError):
            await repository.delete(LDAPSubject(id="x"))


# =============================================================================
# Authentication
# =============================================================================


class TestLDAPAuthentication:
    @pytest.mark.anyio
    async def test_authenticate_valid_credentials(
        self, ldap_config: LDAPConfig
    ) -> None:
        user = await authenticate_user(ldap_config, "alice@example.com", "alicepass")
        assert user is not None
        assert user.email == "alice@example.com"

    @pytest.mark.anyio
    async def test_authenticate_wrong_password(self, ldap_config: LDAPConfig) -> None:
        user = await authenticate_user(ldap_config, "alice@example.com", "wrongpass")
        assert user is None

    @pytest.mark.anyio
    async def test_authenticate_unknown_user(self, ldap_config: LDAPConfig) -> None:
        user = await authenticate_user(ldap_config, "ghost@example.com", "anypass")
        assert user is None

    @pytest.mark.anyio
    async def test_authenticate_empty_password(self, ldap_config: LDAPConfig) -> None:
        # Empty passwords are LDAP anonymous bind -- always reject
        user = await authenticate_user(ldap_config, "alice@example.com", "")
        assert user is None

    @pytest.mark.anyio
    async def test_authenticate_by_username(self, ldap_config: LDAPConfig) -> None:
        user = await authenticate_user(
            ldap_config,
            "alice",
            "alicepass",
            identifier_field="username",
        )
        assert user is not None
        assert user.username == "alice"


# =============================================================================
# Config & Filter Building
# =============================================================================


class TestLDAPFilterBuilding:
    def test_default_filter_with_no_args(self) -> None:
        config = LDAPConfig(
            url="ldap://test",
            user_filter="(objectClass=inetOrgPerson)",
        )
        repo = LDAPSubjectRepository(config)
        result = repo._build_filter({})
        assert result == "(objectClass=inetOrgPerson)"

    def test_filter_with_single_attribute(self) -> None:
        config = LDAPConfig(
            url="ldap://test",
            user_filter="(objectClass=inetOrgPerson)",
        )
        repo = LDAPSubjectRepository(config)
        result = repo._build_filter({"email": "alice@example.com"})
        assert result.startswith("(&")
        assert "(objectClass=inetOrgPerson)" in result
        assert "(mail=alice@example.com)" in result

    def test_filter_escapes_special_chars(self) -> None:
        config = LDAPConfig(url="ldap://test", user_filter="")
        repo = LDAPSubjectRepository(config)
        result = repo._build_filter({"email": "evil*(value)"})
        # *, (, ) should be escaped
        assert "*" not in result.replace("\\2a", "")
        assert "(value)" not in result
        assert "\\28" in result  # escaped (
        assert "\\29" in result  # escaped )
        assert "\\2a" in result  # escaped *

    def test_attribute_map_override(self) -> None:
        # AD uses sAMAccountName instead of uid
        config = LDAPConfig(
            url="ldap://test",
            user_filter="",
            attribute_map=LDAPAttributeMap(
                username="sAMAccountName",
                email="mail",
                id="objectGUID",
            ),
        )
        repo = LDAPSubjectRepository(config)
        result = repo._build_filter({"username": "alice"})
        assert "sAMAccountName=alice" in result


class TestLDAPAttributeMap:
    def test_default(self) -> None:
        attr_map = LDAPAttributeMap()
        assert attr_map.email == "mail"
        assert attr_map.username == "uid"

    def test_attribute_list(self) -> None:
        attr_map = LDAPAttributeMap()
        attrs = attr_map.attribute_list()
        assert "mail" in attrs
        assert "uid" in attrs
        assert "displayName" in attrs

    def test_custom_mapping(self) -> None:
        attr_map = LDAPAttributeMap(
            username="sAMAccountName",
            email="mail",
        )
        assert attr_map.username == "sAMAccountName"
        attrs = attr_map.attribute_list()
        assert "sAMAccountName" in attrs
