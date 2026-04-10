"""Pre-built email templates for NeoZen notifications.

These templates produce `EmailMessage` instances ready to send via
any `EmailSenderProtocol` implementation. Each template has both
plain text and HTML versions.
"""

from __future__ import annotations

from datetime import datetime

from neozen.core.email.base import EmailMessage


def _format_minutes(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes == 1:
        return "1 minute"
    return f"{minutes} minutes"


def _expiry_text(expires_at: datetime) -> str:
    return expires_at.strftime("%Y-%m-%d %H:%M UTC")


# =============================================================================
# Password Reset
# =============================================================================


def password_reset_email(
    *,
    to: str,
    reset_url: str,
    expires_at: datetime,
    app_name: str = "NeoZen",
) -> EmailMessage:
    """Build a password reset email.

    Args:
        to: Recipient email.
        reset_url: Full URL containing the reset token.
        expires_at: Token expiration timestamp.
        app_name: Application name for the subject line.
    """
    expiry = _expiry_text(expires_at)
    body_text = (
        f"Hello,\n\n"
        f"We received a request to reset your password.\n"
        f"Click this link to set a new password:\n\n"
        f"{reset_url}\n\n"
        f"This link expires at {expiry}.\n"
        f"If you didn't request this, you can safely ignore this email."
    )
    body_html = (
        f"<p>Hello,</p>"
        f"<p>We received a request to reset your password.</p>"
        f'<p><a href="{reset_url}">Reset your password</a></p>'
        f"<p>This link expires at <strong>{expiry}</strong>.</p>"
        f"<p>If you didn't request this, you can safely ignore this email.</p>"
    )
    return EmailMessage(
        to=to,
        subject=f"Reset your {app_name} password",
        body_text=body_text,
        body_html=body_html,
    )


# =============================================================================
# Email Verification
# =============================================================================


def email_verification_email(
    *,
    to: str,
    verify_url: str,
    expires_at: datetime,
    app_name: str = "NeoZen",
) -> EmailMessage:
    """Build an email verification message."""
    expiry = _expiry_text(expires_at)
    body_text = (
        f"Welcome to {app_name}!\n\n"
        f"Please verify your email address by clicking this link:\n\n"
        f"{verify_url}\n\n"
        f"This link expires at {expiry}."
    )
    body_html = (
        f"<p>Welcome to {app_name}!</p>"
        f"<p>Please verify your email address by clicking the link below:</p>"
        f'<p><a href="{verify_url}">Verify email</a></p>'
        f"<p>This link expires at <strong>{expiry}</strong>.</p>"
    )
    return EmailMessage(
        to=to,
        subject=f"Verify your {app_name} email",
        body_text=body_text,
        body_html=body_html,
    )


# =============================================================================
# Email OTP
# =============================================================================


def email_otp_email(
    *,
    to: str,
    code: str,
    lifetime_seconds: int,
    app_name: str = "NeoZen",
) -> EmailMessage:
    """Build an email containing a one-time password code."""
    lifetime = _format_minutes(lifetime_seconds)
    body_text = (
        f"Your {app_name} verification code is:\n\n"
        f"    {code}\n\n"
        f"This code expires in {lifetime}.\n"
        f"If you didn't request this, you can ignore this email."
    )
    body_html = (
        f"<p>Your {app_name} verification code is:</p>"
        f'<p style="font-size: 24px; font-weight: bold; '
        f'letter-spacing: 4px;">{code}</p>'
        f"<p>This code expires in {lifetime}.</p>"
        f"<p>If you didn't request this, you can ignore this email.</p>"
    )
    return EmailMessage(
        to=to,
        subject=f"{app_name} verification code: {code}",
        body_text=body_text,
        body_html=body_html,
    )


# =============================================================================
# Account Lockout Notification
# =============================================================================


def account_lockout_email(
    *,
    to: str,
    locked_until: datetime,
    failed_attempts: int,
    ip_address: str | None = None,
    app_name: str = "NeoZen",
) -> EmailMessage:
    """Notify a user that their account has been locked."""
    until = _expiry_text(locked_until)
    ip_line = f"\n  IP address: {ip_address}" if ip_address else ""
    body_text = (
        f"Hello,\n\n"
        f"Your {app_name} account has been temporarily locked due to "
        f"{failed_attempts} failed login attempts.\n\n"
        f"Locked until: {until}{ip_line}\n\n"
        f"If this wasn't you, please reset your password as soon as the "
        f"lockout expires."
    )
    body_html = (
        f"<p>Hello,</p>"
        f"<p>Your <strong>{app_name}</strong> account has been temporarily "
        f"locked due to <strong>{failed_attempts}</strong> failed login "
        f"attempts.</p>"
        f"<p>Locked until: <strong>{until}</strong></p>"
    )
    if ip_address:
        body_html += f"<p>IP address: <code>{ip_address}</code></p>"
    body_html += (
        "<p>If this wasn't you, please reset your password as soon as the "
        "lockout expires.</p>"
    )
    return EmailMessage(
        to=to,
        subject=f"{app_name} account locked",
        body_text=body_text,
        body_html=body_html,
    )


# =============================================================================
# Compromised Password Alert
# =============================================================================


def compromised_password_email(
    *,
    to: str,
    app_name: str = "NeoZen",
) -> EmailMessage:
    """Alert a user that their password was found in a breach.

    Sent when a `check_breached` policy detects the password in a
    known breach database (e.g., Have I Been Pwned).
    """
    body_text = (
        f"Hello,\n\n"
        f"We detected that your {app_name} password appears in a known "
        f"data breach. Your account has not been compromised, but you "
        f"should change your password immediately.\n\n"
        f"Please log in and update your password as soon as possible."
    )
    body_html = (
        f"<p>Hello,</p>"
        f"<p>We detected that your <strong>{app_name}</strong> password "
        f"appears in a known data breach.</p>"
        f"<p>Your account has not been compromised, but you should change "
        f"your password immediately.</p>"
        f"<p>Please log in and update your password as soon as possible.</p>"
    )
    return EmailMessage(
        to=to,
        subject=f"Action required: Update your {app_name} password",
        body_text=body_text,
        body_html=body_html,
    )


__all__ = [
    "account_lockout_email",
    "compromised_password_email",
    "email_otp_email",
    "email_verification_email",
    "password_reset_email",
]
