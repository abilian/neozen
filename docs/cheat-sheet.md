# Cheat Sheet

Everything essential on one page — focused on the **library /
embed-in-your-app** path. If you're looking for the
`docker compose up` self-hosted IAM path, see the
[Self-Hosted Quickstart](getting-started/self-hosted.md) instead.

## Install

```bash
uv add neozen
uv add "neozen[password,totp,webauthn,oauth]"  # all extras
```

## Database Setup

```python
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from neozen.storage.sqlalchemy.base import Base

engine = create_async_engine("sqlite+aiosqlite:///data/app.db")
async with engine.begin() as conn:
    await conn.run_sync(Base.metadata.create_all)
session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
```

## Register a User

```python
import secrets
from pwdlib import PasswordHash
from neozen.storage.sqlalchemy.repositories import SubjectRepository

hasher = PasswordHash.recommended()

async with session_factory() as db:
    repo = SubjectRepository(session=db)
    subject_id = f"user_{secrets.token_hex(8)}"
    await repo.create(
        id=subject_id,
        email="alice@example.com",
        hashed_password=hasher.hash("password123"),
        is_active=True,
        is_verified=False,
    )
    await db.commit()
```

## Password Authentication

```python
from neozen.core.factors.password import create_password_factor
from neozen.core.identifiers.email import create_email_identifier

async with session_factory() as db:
    repo = SubjectRepository(session=db)
    identifier = create_email_identifier(repo)
    factor = create_password_factor(identifier, repo, hasher)

    user = await factor.authenticate({
        "identifier": "alice@example.com",
        "password": "password123",
    })
```

## Sessions

```python
from neozen.storage.sqlalchemy import SessionServiceFactory

session_service = SessionServiceFactory(session_factory, secret_key="change-me")

# Create
token = await session_service.create_session(user.id, ip_address="1.2.3.4")

# Validate
session = await session_service.validate_session(token)

# Revoke
await session_service.revoke_session_by_token(token)

# List
sessions = await session_service.list_sessions(user.id)
```

## Magic Link

```python
from neozen.core.factors.magic_link import MagicLinkFactor, MagicLinkConfig
from neozen.core.email.console import ConsoleEmailSender

factor = MagicLinkFactor(
    config=MagicLinkConfig(link_base_url="https://app.com/magic-login/verify"),
    token_repository=token_repo,
    subject_email_lookup=email_lookup,
    email_sender=ConsoleEmailSender(),
    token_hash_key="secret",
)

# Send link (always returns success — anti-enumeration)
await factor.begin_authentication(user.id, ip_address="1.2.3.4")

# Verify (in callback handler)
valid = await factor.complete_authentication(user.id, response=token)
```

## TOTP / 2FA

```python
from neozen.core.factors.totp import TOTPFactor, TOTPConfig

totp = TOTPFactor(
    config=TOTPConfig(issuer="My App"),
    subject_repository=user_repo,
    backup_code_repository=backup_repo,
    hasher=hasher,
)

# Enroll
enrollment = await totp.begin_enrollment(user, account_name=user.email)
# Show enrollment.qr_code_data_uri to user
user, backup_codes = await totp.confirm_enrollment(user, code="123456")

# Authenticate
valid = await totp.authenticate(user, code="123456")
# Backup codes also work
valid = await totp.authenticate(user, code="ABCD1234")
```

## Authorization (RBAC)

```python
from neozen.storage.sqlalchemy import RoleServiceFactory, get_subject_roles
from neozen.core.authz.models import Permission

role_service = RoleServiceFactory(session_factory)

# Assign / revoke
await role_service.assign_role(user.id, "admin")
await role_service.revoke_role(user.id, "admin")

# Check
roles = await get_subject_roles(session_factory, user.id)
if "admin" in roles:
    ...

# Permission format: resource:action[:scope]
Permission.parse("user:read")
Permission.parse("document:write:own")
Permission.parse("*:*")  # superuser
```

**Built-in roles**: `superuser` (`*:*`), `admin` (`user:*`, `role:*`, `client:*`), `user` (`*:*:own`)

## Flask Integration

```python
from flask import Flask
from neozen.ext.flask import NeoZen, current_user, login_required, login_user, logout_user
from neozen.storage.sqlalchemy import create_subject_loader

app = Flask(__name__)
app.secret_key = "change-me"

neozen = NeoZen(
    app,
    session_service=session_service,
    subject_loader=create_subject_loader(session_factory),
)

@app.route("/login", methods=["POST"])
def login():
    user = User.get_by_email(request.form["email"])
    if user and user.check_password(request.form["password"]):
        login_user(user, remember=True)
        return redirect("/dashboard")

@app.route("/dashboard")
@login_required
def dashboard():
    return f"Hello {current_user.email}"

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect("/")
```

## Litestar Integration

```python
from litestar import Litestar, Request, get, post
from litestar.response import Redirect
from neozen.ext.litestar import (
    NeoZenConfig, NeoZenPlugin,
    get_current_user, login_required, login_user, logout_user,
)

neozen_config = NeoZenConfig(
    session_service=session_service,
    subject_loader=create_subject_loader(session_factory),
    cookie_secure=False,
)

@post("/login")
async def login_submit(request: Request) -> Response:
    form = await request.form()
    # ... verify credentials ...
    response = Redirect(path="/dashboard")
    await login_user(request, response, subject)
    return response

@get("/dashboard", guards=[login_required()])
async def dashboard(request: Request) -> Response:
    user = await get_current_user(request)
    return Response(content=f"Hello {user.email}")

app = Litestar(route_handlers=[...], plugins=[NeoZenPlugin(neozen_config)])
```

## OAuth Social Login

```python
from neozen.core.oauth_client.service import OAuthClientService
from neozen.core.oauth_client.providers.google import GoogleProvider

service = OAuthClientService(social_account_repo, state_repo, http_client=httpx.AsyncClient())
service.register_provider(GoogleProvider(config=google_config, http_client=http))

# Step 1: redirect user to provider
result = service.begin_authorization("google", redirect_uri="https://app.com/callback")
return redirect(result.authorization_url)

# Step 2: handle callback
callback = await service.handle_callback("google", code=code, state=state, redirect_uri=...)
subject_id, is_new = await service.get_or_create_subject_id(callback)

# Refresh expired tokens
new_tokens = await service.refresh_access_token("google", refresh_token)
```

## Bring Your Own Model

```python
from neozen.core.identifiers.email import create_email_identifier
from neozen.core.factors.password import create_password_factor

# No type: ignore needed — factories accept Any-typed storage
identifier = create_email_identifier(my_user_repo_adapter)
factor = create_password_factor(identifier, my_user_repo_adapter, hasher)
```

Adapter only needs `get_one_by(**filters)` and `update_obj(obj, **data)` for `PasswordFactor`.

## Email

```python
from neozen.core.email.base import EmailMessage
from neozen.core.email.console import ConsoleEmailSender   # dev
from neozen.core.email.smtp import SMTPEmailSender         # prod

sender = SMTPEmailSender(host="smtp.example.com", port=587, username="u", password="p", use_tls=True)
await sender.send(EmailMessage(to="user@example.com", subject="Hello", body_text="Hi!"))
```

## Configuration Defaults

| Setting | Default |
|---------|---------|
| Session lifetime | 7 days |
| Sliding window | 1 hour |
| Magic link lifetime | 15 minutes |
| Magic link rate limit | 3 pending / hour |
| Password reset lifetime | 1 hour |
| TOTP digits | 6 |
| TOTP interval | 30s |
| TOTP backup codes | 8 |

## Token Prefixes

| Prefix | Purpose |
|--------|---------|
| `nz_session_` | Session token |
| `nz_ev_` | Email verification |
| `nz_ml_` | Magic link |
| `nz_pr_` | Password reset |
| `nz_at_` / `nz_rt_` / `nz_ac_` | OAuth tokens |

## Email OTP

```python
from neozen.core.factors.email_otp import EmailOTPFactor, EmailOTPConfig

factor = EmailOTPFactor(
    config=EmailOTPConfig(),
    code_repository=otp_repo,
    subject_email_lookup=email_lookup,
    email_sender=sender,
    code_hash_key="secret",
)

# Send a code
await factor.begin_authentication(user_id)

# Verify
ok = await factor.complete_authentication(user_id, response="123456")
```

## Groups

```python
from neozen.core.groups import GroupService, GroupRole

service = GroupService(group_repository=g_repo, membership_repository=m_repo)

group = await service.create_group("engineering", owner_id="user_1")
await service.add_member(group.id, "user_2", actor_id="user_1")
await service.change_role(group.id, "user_2", GroupRole.ADMIN, actor_id="user_1")
members = await service.list_members(group.id)
```

## Invitations

```python
from neozen.core.groups import InvitationService, InvitationConfig

service = InvitationService(
    config=InvitationConfig(
        accept_url_template="https://app.com/invite?token={token}",
    ),
    repository=inv_repo,
    token_hash_key="secret",
)

# Create
invitation, token = await service.create_invitation(
    email="new@example.com",
    invited_by="admin_1",
    group_ids=["grp_1"],
    role_names=["user"],
)

# Accept
details = await service.accept_invitation(token, accepted_by=new_user_id)
```

## OIDC Provider

```python
from neozen.core.oidc import InMemoryKeyManager, IDTokenGenerator
from neozen.web.oidc import (
    DiscoveryEndpoint, JWKSEndpoint, UserInfoEndpoint,
    EndSessionEndpoint, RegistrationEndpoint,
)
from neozen.core.oidc.discovery import build_metadata_from_base_url

key_manager = InMemoryKeyManager()
id_token_gen = IDTokenGenerator(
    key_manager=key_manager, issuer="https://auth.example.com",
)

# Wire OIDC into the OAuth token endpoint
endpoint = TokenEndpoint(
    oauth_token_service,
    id_token_generator=id_token_gen,
    claims_provider=claims_provider,
)

# HTTP endpoints
metadata = build_metadata_from_base_url(
    issuer="https://auth.example.com",
    base_url="https://auth.example.com",
)
discovery = DiscoveryEndpoint(metadata)
jwks = JWKSEndpoint(key_manager)
userinfo = UserInfoEndpoint(oauth_token_service, claims_provider)
```

## SCIM 2.0

```python
from neozen.core.scim import SCIMUserService, SCIMGroupService, User, Email
from neozen.web.scim import UsersEndpoint, GroupsEndpoint, DiscoveryEndpoints

user_service = SCIMUserService(
    adapter=my_adapter,
    base_url="https://api.example.com/scim/v2",
)
users = UsersEndpoint(user_service)

# Create
result = await users.create({"userName": "alice", "emails": [...]})

# List with filter
result = await users.list({"filter": 'userName sw "ali"', "count": 10})

# Discovery
discovery = DiscoveryEndpoints()
```

## LDAP Backend

```python
from neozen.storage.ldap import LDAPConfig, LDAPSubjectRepository, authenticate_user

config = LDAPConfig(
    url="ldap://ldap.example.com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="secret",
    base_dn="ou=people,dc=example,dc=com",
)

repo = LDAPSubjectRepository(config)
user = await repo.get_one_by(email="alice@example.com")

# Bind authentication
user = await authenticate_user(config, "alice@example.com", "password")
```

## i18n

```python
from neozen.core.i18n import builtin_translator, negotiate_locale, Catalog

# Use the built-in translator (EN/FR for emails and errors)
msg = builtin_translator.gettext(
    "email.password_reset.subject",
    locale="fr",
    app_name="My App",
)

# Add a custom locale
builtin_translator.add_catalog("de", Catalog({...}))

# Negotiate from request
locale = negotiate_locale(
    ui_locales=request.params.get("ui_locales"),
    user_preference=user.locale,
    accept_language=request.headers.get("Accept-Language"),
    available=["en", "fr", "de"],
    default="en",
)
```

## Common Imports

```python
# Factors
from neozen.core.factors.password import PasswordFactor, create_password_factor
from neozen.core.factors.totp import TOTPFactor, TOTPConfig
from neozen.core.factors.magic_link import MagicLinkFactor, MagicLinkConfig
from neozen.core.factors.email_otp import EmailOTPFactor, EmailOTPConfig

# Identifiers
from neozen.core.identifiers.email import EmailIdentifier, create_email_identifier

# Sessions
from neozen.storage.sqlalchemy import SessionServiceFactory

# Authorization
from neozen.storage.sqlalchemy import RoleServiceFactory, get_subject_roles
from neozen.core.authz.models import Permission, Role, RoleAssignment, ScopeType

# Groups & Invitations
from neozen.core.groups import GroupService, GroupRole, InvitationService

# Email
from neozen.core.email.base import EmailMessage, EmailSenderProtocol
from neozen.core.email.console import ConsoleEmailSender
from neozen.core.email.smtp import SMTPEmailSender
from neozen.core.email.notifications import NotificationService

# OAuth client
from neozen.core.oauth_client.service import OAuthClientService
from neozen.core.oauth_client.providers.google import GoogleProvider
from neozen.core.oauth_client.providers.github import GitHubProvider

# OIDC Provider
from neozen.core.oidc import InMemoryKeyManager, IDTokenGenerator, DefaultClaimsProvider
from neozen.core.oidc.discovery import build_metadata_from_base_url
from neozen.web.oidc import (
    DiscoveryEndpoint, JWKSEndpoint, UserInfoEndpoint,
    EndSessionEndpoint, RegistrationEndpoint,
)

# SCIM
from neozen.core.scim import SCIMUserService, SCIMGroupService, User, Group, Email
from neozen.web.scim import UsersEndpoint, GroupsEndpoint, DiscoveryEndpoints

# LDAP
from neozen.storage.ldap import LDAPConfig, LDAPSubjectRepository, authenticate_user

# i18n
from neozen.core.i18n import Translator, Catalog, builtin_translator, negotiate_locale

# Storage
from neozen.storage.sqlalchemy.repositories import SubjectRepository
from neozen.storage.sqlalchemy.base import Base
from neozen.core.repository import DoesNotExist, ReadableRepositoryProtocol, WritableRepositoryProtocol

# Framework extensions
from neozen.ext.flask import NeoZen, current_user, login_required, login_user, logout_user
from neozen.ext.litestar import NeoZenConfig, NeoZenPlugin, login_required, login_user, logout_user
```
