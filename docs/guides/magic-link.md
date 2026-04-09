# Magic Link Authentication

Magic links enable passwordless sign-in: the user enters their email,
receives a link, and clicking it authenticates them. NeoZen implements
this as a `ChallengingFactorProtocol` factor.

## How It Works

```
User enters email  ──>  Server generates token  ──>  Email sent
                                                        │
User clicks link   ──>  Server verifies token   ──>  Logged in
```

1. `begin_authentication()` generates a token, stores its hash, sends the email
2. `complete_authentication()` verifies the token, marks it used, logs the user in

## Setup

```python
from neozen.core.factors.magic_link import MagicLinkFactor, MagicLinkConfig
from neozen.core.email.console import ConsoleEmailSender

# Email sender (use SMTPEmailSender in production)
email_sender = ConsoleEmailSender()

# Subject lookup adapter
class SubjectEmailLookup:
    def __init__(self, session_factory):
        self._sf = session_factory

    async def get_email(self, subject_id: str) -> str | None:
        async with self._sf() as s:
            repo = SubjectRepository(session=s)
            try:
                subject = await repo.get_one_by(id=subject_id)
                return subject.email
            except DoesNotExist:
                return None

    async def subject_exists(self, subject_id: str) -> bool:
        async with self._sf() as s:
            repo = SubjectRepository(session=s)
            return await repo.exists(id=subject_id)

# Token repository (in-memory for dev, SQLAlchemy for production)
from neozen.storage.sqlalchemy.security_repositories import (
    SQLAlchemyMagicLinkTokenRepository,
)
token_repo = SQLAlchemyMagicLinkTokenRepository(session_factory)

# Factor
factor = MagicLinkFactor(
    config=MagicLinkConfig(
        link_base_url="https://myapp.com/magic-login/verify",
        token_lifetime=timedelta(minutes=15),
        max_pending_per_subject=3,
    ),
    token_repository=token_repo,
    subject_email_lookup=SubjectEmailLookup(session_factory),
    email_sender=email_sender,
    token_hash_key="your-secret-key",
)
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `token_lifetime` | 15 minutes | How long links are valid |
| `max_pending_per_subject` | 3 | Rate limit per user |
| `rate_limit_window` | 1 hour | Window for rate limiting |
| `token_prefix` | `nz_ml_` | Token prefix |
| `link_base_url` | (required) | URL for the verify endpoint |

## Request a Magic Link

```python
# Always returns success to prevent email enumeration
result = await factor.begin_authentication(
    subject_id,
    ip_address=request.remote_addr,
)
# result = {"status": "sent", "message": "...", "expires_at": "..."}
```

## Verify and Log In

```python
# token comes from the ?token= query parameter
valid = await factor.complete_authentication(
    subject_id=token_record.subject_id,
    response=token,
)

if valid:
    # Create session, redirect to dashboard
    ...
```

!!! note "Finding the subject"
    The token is opaque -- to find which subject it belongs to,
    hash it and look up the token record:

    ```python
    from neozen.core.crypto import get_token_hash

    token_hash = get_token_hash(token, secret_key)
    record = await token_repo.get_by_hash(token_hash)
    subject_id = record.subject_id
    ```

## Security

- Tokens are **single-use** -- marked as used after verification
- **Short expiry** -- 15 minutes by default
- **Rate limited** -- max 3 pending tokens per subject
- **Hash stored** -- only the HMAC-SHA256 hash is in the database
- **Anti-enumeration** -- response never reveals whether the email exists
- **Cascade invalidation** -- using one token invalidates all others

## Email Content

The factor sends an `EmailMessage` via the configured sender:

- **Plain text**: Link URL with expiry notice
- **HTML**: Styled "Sign in" button

In development, use `ConsoleEmailSender` which prints to stdout.
In production, use `SMTPEmailSender` or implement `EmailSenderProtocol`.
