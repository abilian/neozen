"""Session models for NeoZen."""

from __future__ import annotations

import typing
from datetime import datetime

from neozen.core.models import NeoZenModel


class SessionModel(NeoZenModel):
    """Base model for session implementations.

    Sessions represent authenticated user sessions and track:
    - The authenticated subject
    - Session metadata (IP, user agent)
    - Expiration and activity timestamps
    - Revocation status

    Attributes:
        token_hash: HMAC-SHA256 hash of the session token.
        subject_id: The ID of the authenticated subject.
        ip_address: Client IP address at session creation.
        user_agent: Client user agent string.
        created_at: When the session was created.
        expires_at: When the session expires.
        last_activity_at: Last time the session was used.
        revoked_at: When the session was revoked (None if active).

    """

    token_hash: str
    subject_id: typing.Any
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime
    revoked_at: datetime | None


__all__ = ["SessionModel"]
