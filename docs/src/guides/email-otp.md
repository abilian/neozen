# Email OTP

`EmailOTPFactor` signs users in with short numeric codes
sent by email. It suits users who don't have an authenticator
app, or as a step-up factor for sensitive actions.

## Setup

```python
from neozen.core.factors.email_otp import EmailOTPConfig, EmailOTPFactor

factor = EmailOTPFactor(
    config=EmailOTPConfig(
        code_length=6,
        code_lifetime=timedelta(minutes=10),
        max_pending_per_subject=3,
        max_attempts=5,
        app_name="My App",
    ),
    code_repository=otp_repo,
    subject_email_lookup=email_lookup,
    email_sender=sender,  # any EmailSenderProtocol
    code_hash_key="secret",
)
```

## Flow

```python
# 1. User requests a code
result = await factor.begin_authentication(user_id)
# Always returns success-shaped response (anti-enumeration)

# 2. User enters the code from their email
ok = await factor.complete_authentication(user_id, response="123456")
if ok:
    # Authenticated -- proceed with login or step-up
    ...
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `code_length` | 6 | Number of digits |
| `code_lifetime` | 10 minutes | How long codes are valid |
| `max_pending_per_subject` | 3 | Rate limit on active codes |
| `rate_limit_window` | 1 hour | Window for rate limiting |
| `max_attempts` | 5 | Max verification attempts before invalidation |
| `app_name` | `"NeoZen"` | Name shown in email |

## Security

- Codes are short (6 digits) and short-lived (10 minutes)
- Hashes (HMAC-SHA256) are stored, not plain codes
- Rate limited per subject
- Single-use: marked as used after verification
- Max attempts: codes are invalidated after too many wrong guesses
- Constant-time comparison
- Anti-enumeration: response never reveals whether the email exists
