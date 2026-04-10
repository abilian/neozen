"""LDAP backend configuration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LDAPAttributeMap:
    """Maps LDAP attributes to Subject fields.

    Default mapping uses common inetOrgPerson attributes:
    - id <- uid (or entryUUID for OpenLDAP)
    - email <- mail
    - username <- uid
    - display_name <- cn or displayName
    - given_name <- givenName
    - family_name <- sn

    Override these for non-standard schemas (e.g., Active Directory
    uses sAMAccountName instead of uid).
    """

    id: str = "uid"
    email: str = "mail"
    username: str = "uid"
    display_name: str = "displayName"
    given_name: str = "givenName"
    family_name: str = "sn"
    object_class: str = "objectClass"

    def attribute_list(self) -> list[str]:
        """Return the list of attributes to fetch in LDAP searches."""
        return [
            self.id,
            self.email,
            self.username,
            self.display_name,
            self.given_name,
            self.family_name,
        ]


@dataclass(frozen=True)
class LDAPConfig:
    """LDAP server connection configuration.

    Attributes:
        url: LDAP server URL (`ldap://host:port` or `ldaps://...`).
        bind_dn: DN to bind as for searching (admin/service account).
        bind_password: Password for the bind DN.
        base_dn: Base DN for user searches.
        user_filter: Additional filter applied to all user searches
            (e.g., `(objectClass=inetOrgPerson)`). Combined with
            attribute filters via `&`.
        use_ssl: Use ldaps:// (set automatically if URL starts with
            "ldaps://").
        connect_timeout: Connection timeout in seconds.
        receive_timeout: Receive timeout in seconds.
        attribute_map: How to map LDAP attributes to Subject fields.
    """

    url: str
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_filter: str = "(objectClass=inetOrgPerson)"
    use_ssl: bool = False
    connect_timeout: float = 5.0
    receive_timeout: float = 10.0
    attribute_map: LDAPAttributeMap = field(default_factory=LDAPAttributeMap)


__all__ = [
    "LDAPAttributeMap",
    "LDAPConfig",
]
