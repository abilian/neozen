"""JWT access tokens (RFC 9068).

Resource servers can verify these offline against the server's JWKS. The
token service still stores their hash, like an opaque token's, so
revocation and introspection work unchanged.
"""

from __future__ import annotations

import secrets
import typing
from dataclasses import dataclass

if typing.TYPE_CHECKING:
    from datetime import datetime

    from neozen.core.oidc.keys import KeyManager


@dataclass(frozen=True)
class JWTAccessTokenSigner:
    """Signs access tokens with the active key of `key_manager`."""

    key_manager: KeyManager
    issuer: str
    audience: str

    async def sign(
        self,
        *,
        subject_id: typing.Any,
        client_id: str,
        scope: str | None,
        issued_at: datetime,
        expires_at: datetime,
    ) -> str:
        """Return a signed `at+jwt` access token."""
        # Lazy import: pyjwt is an optional extra
        import jwt  # noqa: PLC0415

        signing_key = await self.key_manager.get_active_signing_key()
        claims: dict[str, typing.Any] = {
            "iss": self.issuer,
            "sub": str(subject_id),
            "aud": self.audience,
            "client_id": client_id,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": secrets.token_urlsafe(16),
        }
        if scope:
            claims["scope"] = scope
        return jwt.encode(
            claims,
            signing_key.private_pem,
            algorithm=signing_key.alg,
            headers={"kid": signing_key.kid, "typ": "at+jwt"},
        )


__all__ = ["JWTAccessTokenSigner"]
