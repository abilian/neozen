# Session Management Reference

**Module**: `neozen.core.session.service`

## SessionService

```python
from neozen.core.session.service import SessionService

service = SessionService(
    storage=session_repo,
    hash_key="your-secret-key",
    token_prefix="nz_session_",
    session_lifetime_seconds=604800,     # 7 days
    sliding_window_seconds=3600,          # 1 hour
    max_sessions_per_subject=None,        # unlimited
)
```

In production, set `max_sessions_per_subject` to 5–10: enough for a user's devices, while a stolen password can't open sessions without limit. When a subject reaches the limit, signing in again ends its oldest session.

### Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `create_session(subject_id, *, ip_address, user_agent)` | Start a new session | Plaintext token |
| `validate_session(token, *, update_activity)` | Verify token, check expiry | Session record |
| `revoke_session(token_hash)` | Revoke by hash | None |
| `revoke_session_by_token(token)` | Revoke by plaintext token | None |
| `revoke_all_sessions(subject_id)` | Revoke all for subject | Count revoked |
| `list_sessions(subject_id, *, include_expired, include_revoked)` | List sessions | List of sessions |

### Exceptions

- `SessionNotFoundError` -- token not in storage
- `SessionExpiredError` -- session past expiration
- `SessionRevokedError` -- session was revoked

## SessionServiceFactory

This convenience wrapper manages the database session lifecycle:

```python
from neozen.storage.sqlalchemy import SessionServiceFactory

factory = SessionServiceFactory(session_factory, secret_key)

# Create
token = await factory.create_session("user_123", ip_address="1.2.3.4")

# Validate
session = await factory.validate_session(token)

# Revoke
await factory.revoke_session_by_token(token)
```

## Session Model

| Field | Type | Description |
|-------|------|-------------|
| `token_hash` | str | HMAC-SHA256 hash (primary key) |
| `subject_id` | str | Authenticated subject |
| `ip_address` | str \| None | Client IP at creation |
| `user_agent` | str \| None | Client user agent |
| `created_at` | datetime | Session start |
| `expires_at` | datetime | Expiration time |
| `last_activity_at` | datetime | Last request |
| `revoked_at` | datetime \| None | Revocation time |

## Sliding Window

When `sliding_window_seconds` is set, each successful `validate_session()` call extends `expires_at` by that duration (if the remaining time is less than the window).

## Token Format

Session tokens use the standard NeoZen token format:

- Prefix: `nz_session_`
- 37 random characters + 6-char CRC32 checksum
- Only the HMAC-SHA256 hash is stored
