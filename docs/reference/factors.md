# Factors Reference

## PasswordFactor

**Module**: `neozen.core.factors.password`

**Protocol**: `AuthenticatingFactorProtocol`

```python
from neozen.core.factors.password import PasswordFactor, create_password_factor

# Generic (type-safe with NeoZen models)
factor = PasswordFactor(identifier, subject_storage, hasher)

# Non-generic (for custom models)
factor = create_password_factor(identifier, subject_storage, hasher)
```

### Methods

| Method | Description |
|--------|-------------|
| `authenticate(payload)` | Verify `{"identifier": ..., "password": ...}` |
| `enroll(subject, payload)` | Set initial password |
| `change_password(subject, old, new)` | Change password (verifies old) |

### Exceptions

- `InvalidCredentialsError` -- wrong password or user not found
- `PasswordFactorError` -- base exception for password errors

### Security

- Timing-safe comparison via `hmac.compare_digest`
- Dummy hash on user-not-found to prevent timing attacks
- Automatic hash upgrade on successful login

---

## MagicLinkFactor

**Module**: `neozen.core.factors.magic_link`

**Protocol**: `ChallengingFactorProtocol`

```python
from neozen.core.factors.magic_link import MagicLinkFactor, MagicLinkConfig

factor = MagicLinkFactor(
    config=MagicLinkConfig(link_base_url="https://app.com/verify"),
    token_repository=token_repo,
    subject_email_lookup=email_lookup,
    email_sender=email_sender,
    token_hash_key="secret",
)
```

### Methods

| Method | Description |
|--------|-------------|
| `begin_authentication(subject_id)` | Generate token, send email |
| `complete_authentication(subject_id, response=token)` | Verify token |
| `is_enrolled(subject_id)` | True if subject has an email |

### Required Protocols

- `MagicLinkTokenRepository` -- `create`, `get_by_hash`, `mark_used`, `count_pending`, `invalidate_all`
- `SubjectEmailLookup` -- `get_email(subject_id)`, `subject_exists(subject_id)`
- `EmailSenderProtocol` -- `send(EmailMessage)`

---

## TOTPFactor

**Module**: `neozen.core.factors.totp`

**Protocols**: `EnrollableFactorProtocol`

```python
from neozen.core.factors.totp import TOTPFactor, TOTPConfig

factor = TOTPFactor(
    config=TOTPConfig(issuer="My App"),
    subject_repository=repo,
    backup_code_repository=backup_repo,
    hasher=password_hasher,
)
```

### Methods

| Method | Description |
|--------|-------------|
| `begin_enrollment(subject, account_name)` | Generate secret + QR code |
| `confirm_enrollment(subject, code)` | Verify code and enable TOTP |
| `authenticate(subject, code)` | Verify TOTP or backup code |
| `unenroll(subject)` | Disable TOTP |

### Dependencies

Requires `pyotp` (`uv add "neozen[totp]"`). Optional `qrcode` for QR data URIs.

---

## WebAuthnFactor

**Module**: `neozen.core.factors.webauthn`

**Protocols**: `EnrollableFactorProtocol` + `ChallengingFactorProtocol`

```python
from neozen.core.factors.webauthn import WebAuthnFactor, WebAuthnConfig

factor = WebAuthnFactor(
    config=WebAuthnConfig(
        rp_id="localhost",
        rp_name="My App",
        origin="http://localhost:8000",
    ),
    credential_repository=cred_repo,
    challenge_repository=challenge_repo,
)
```

### Methods

| Method | Description |
|--------|-------------|
| `begin_registration(subject_id)` | Generate registration options |
| `complete_registration(subject_id, credential)` | Store credential |
| `begin_authentication(subject_id)` | Generate authentication challenge |
| `complete_authentication(subject_id, response)` | Verify assertion |

### Dependencies

Requires `py-webauthn` (`uv add "neozen[webauthn]"`).
