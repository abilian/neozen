"""LDAP connection management.

ldap3 is synchronous, so connections run inside `to_thread.run_sync`
to keep the rest of NeoZen async.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from anyio import to_thread

if TYPE_CHECKING:
    from neozen.storage.ldap.config import LDAPConfig


class LDAPConnectionError(Exception):
    """Raised when an LDAP connection or operation fails."""


def _build_server(config: LDAPConfig) -> Any:
    """Create an ldap3 Server from config (sync helper)."""
    from ldap3 import Server  # noqa: PLC0415

    return Server(
        config.url,
        use_ssl=config.use_ssl or config.url.startswith("ldaps://"),
        connect_timeout=int(config.connect_timeout),
    )


def _bind(config: LDAPConfig, dn: str | None, password: str | None) -> Any:
    """Bind synchronously and return the ldap3.Connection.

    Returns the connection on success, raises LDAPConnectionError otherwise.
    """
    from ldap3 import Connection  # noqa: PLC0415
    from ldap3.core.exceptions import LDAPException  # noqa: PLC0415

    server = _build_server(config)
    try:
        conn = Connection(
            server,
            user=dn or None,
            password=password or None,
            auto_bind=True,
            receive_timeout=int(config.receive_timeout),
        )
    except LDAPException as e:
        msg = f"LDAP bind failed: {e}"
        raise LDAPConnectionError(msg) from e
    return conn


async def bind_async(
    config: LDAPConfig,
    *,
    dn: str | None = None,
    password: str | None = None,
) -> Any:
    """Bind to the LDAP server in a worker thread.

    If `dn`/`password` are not given, uses the bind_dn/bind_password
    from config (typical for searching).
    """
    actual_dn = dn if dn is not None else config.bind_dn
    actual_password = password if password is not None else config.bind_password

    return await to_thread.run_sync(_bind, config, actual_dn, actual_password)


async def search_async(
    conn: Any,
    *,
    base_dn: str,
    search_filter: str,
    attributes: list[str],
    size_limit: int = 1000,
) -> list[Any]:
    """Run an LDAP search in a worker thread.

    Returns the list of entries (ldap3 entry objects).
    """

    def _search() -> list[Any]:
        from ldap3 import SUBTREE  # noqa: PLC0415
        from ldap3.core.exceptions import LDAPException  # noqa: PLC0415

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

    return await to_thread.run_sync(_search)


async def unbind_async(conn: Any) -> None:
    """Close an LDAP connection in a worker thread."""
    if conn is None:
        return
    await to_thread.run_sync(conn.unbind)


__all__ = [
    "LDAPConnectionError",
    "bind_async",
    "search_async",
    "unbind_async",
]
