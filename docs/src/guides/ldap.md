# LDAP Backend

NeoZen can use LDAP/Active Directory as a read-mostly subject store with bind-based password authentication. The LDAP backend is built on [ldap3][ldap3] (pure Python, no C dependencies).

[ldap3]: https://ldap3.readthedocs.io/

## Installation

```bash
uv add "neozen[ldap]"
```

## Configuration

```python
from neozen.storage.ldap import LDAPConfig, LDAPAttributeMap

config = LDAPConfig(
    url="ldap://ldap.example.com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="secret",
    base_dn="ou=people,dc=example,dc=com",
    user_filter="(objectClass=inetOrgPerson)",
)
```

For non-standard schemas (e.g., Active Directory), override the attribute map:

```python
ad_config = LDAPConfig(
    url="ldaps://ad.example.com",
    bind_dn="CN=svc,OU=Service Accounts,DC=example,DC=com",
    bind_password="secret",
    base_dn="OU=Users,DC=example,DC=com",
    user_filter="(&(objectClass=user)(objectCategory=person))",
    attribute_map=LDAPAttributeMap(
        id="objectGUID",
        username="sAMAccountName",
        email="mail",
        display_name="displayName",
        given_name="givenName",
        family_name="sn",
    ),
)
```

## Looking Up Users

`LDAPSubjectRepository` implements `ReadableRepositoryProtocol`:

```python
from neozen.storage.ldap import LDAPSubjectRepository

repository = LDAPSubjectRepository(config)

# Look up by email
user = await repository.get_one_by(email="alice@example.com")
print(user.display_name, user.dn)

# Look up by username
user = await repository.get_one_by(username="alice")

# List all users
users = await repository.get_many_by(limit=100)

# Count
total = await repository.count()
```

## Authentication

The `authenticate_user` helper performs LDAP bind authentication:

```python
from neozen.storage.ldap import authenticate_user

user = await authenticate_user(
    config,
    "alice@example.com",
    "user-password",
)

if user is None:
    # Either unknown user or wrong password.
    # The function returns None for both to prevent enumeration.
    raise InvalidCredentialsError()

# user.email, user.username, user.dn are populated
```

## How It Works

1. The bind DN/password are used to search the directory for the user
2. If found, NeoZen attempts to bind as that user with the supplied password
3. A successful bind means the password is correct
4. The bound connection is then closed (no session is kept open)

## Read-Only by Default

Write operations (`create`, `update_obj`, `delete`) raise `NotImplementedError` by default. Many LDAP deployments are read-only from the application's perspective. To add write support, subclass `LDAPSubjectRepository` and implement the methods using ldap3's `add()`, `modify()`, and `delete()` operations.

## Filter Building

`LDAPSubjectRepository` turns keyword arguments into RFC 4515 search filters, as follows:

| Kwarg | LDAP filter |
|-------|-------------|
| `email="a@b.com"` | `(mail=a@b.com)` |
| `username="alice"` | `(uid=alice)` |
| `id="alice"` | `(uid=alice)` |

Special characters in values (`*`, `(`, `)`, `\`, `\x00`) are escaped per RFC 4515 to prevent LDAP injection.

## Limitations and Future Work

- **Read-only by default** -- override for write support
- **No connection pooling** -- each operation opens a fresh connection. For high-throughput use, wrap in a pooling layer.
- **No group support yet** -- only Subject lookups
- **No schema discovery** -- attribute mapping is configured manually
