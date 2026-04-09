# TOTP / MFA

NeoZen supports Time-based One-Time Password (TOTP) as a second
authentication factor. Users enroll via a QR code in an authenticator
app (Google Authenticator, Authy, etc.) and verify with 6-digit codes.

## Setup

```python
from neozen.core.factors.totp import TOTPFactor, TOTPConfig

factor = TOTPFactor(
    config=TOTPConfig(
        issuer="My App",
        digits=6,
        interval=30,
        backup_code_count=8,
        backup_code_length=8,
    ),
    subject_repository=user_repo_adapter,
    backup_code_repository=backup_code_repo_adapter,
    hasher=password_hasher,
)
```

## Enrollment

TOTP enrollment is a two-step process:

### Step 1: Begin Enrollment

```python
enrollment = await factor.begin_enrollment(
    user,
    account_name=user.email,
)
# enrollment.provisioning_uri  -- for QR code
# enrollment.secret            -- base32 secret (manual entry)
# enrollment.qr_code_data_uri  -- data URI for <img> tag (if qrcode installed)
```

### Step 2: Confirm with Code

The user enters a code from their authenticator app:

```python
updated_user, backup_codes = await factor.confirm_enrollment(
    user,
    code="123456",  # from authenticator app
)
# backup_codes = ["ABCD1234", "EFGH5678", ...]
# Store/display these for the user
```

## Authentication

After enrollment, verify TOTP codes during login:

```python
valid = await factor.authenticate(user, code="123456")
```

## Backup Codes

If a user loses their authenticator, they can use a backup code:

```python
valid = await factor.authenticate(user, code="ABCD1234")
# Backup codes are single-use -- consumed on verification
```

## Login Flow with 2FA

A typical two-step login flow:

```python
# Step 1: Password
user = await password_factor.authenticate({
    "identifier": email,
    "password": password,
})

# Step 2: Check if TOTP is enabled
if user.totp_enabled:
    # Store user ID in session, redirect to TOTP page
    session["pending_2fa_user_id"] = user.id
    return redirect("/login/totp")

# No 2FA -- log in directly
login_user(user)
```

```python
# TOTP verification page
@app.route("/login/totp", methods=["POST"])
def verify_totp():
    user_id = session.pop("pending_2fa_user_id")
    user = User.get(user_id)
    code = request.form["code"]

    if await totp_factor.authenticate(user, code):
        login_user(user)
        return redirect("/dashboard")

    flash("Invalid code", "error")
    return redirect("/login/totp")
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `issuer` | (required) | App name shown in authenticator |
| `digits` | 6 | Code length |
| `interval` | 30 | Code rotation interval (seconds) |
| `backup_code_count` | 8 | Number of backup codes |
| `backup_code_length` | 8 | Length of each backup code |

## Dependencies

TOTP requires the `totp` extra:

```bash
uv add "neozen[totp]"
```

This installs `pyotp`. QR code generation optionally uses `qrcode`.
