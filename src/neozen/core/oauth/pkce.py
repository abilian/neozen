"""PKCE (Proof Key for Code Exchange) implementation for OAuth 2.1.

RFC 7636: Proof Key for Code Exchange by OAuth Public Clients
https://tools.ietf.org/html/rfc7636
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from neozen.core.oauth.exceptions import PKCEVerificationFailedError
from neozen.core.oauth.types import CodeChallengeMethod


def verify_pkce(
    code_verifier: str,
    code_challenge: str,
    method: CodeChallengeMethod,
) -> None:
    """Verify PKCE code verifier against stored challenge.

    Args:
        code_verifier: The code verifier from the token request.
        code_challenge: The stored code challenge from authorization.
        method: The challenge method ("plain" or "S256").

    Raises:
        PKCEVerificationFailedError: If verification fails.
    """
    # Constant-time comparison on both branches to avoid leaking byte
    # positions via response-time side channel.
    if method == "plain":
        if not hmac.compare_digest(code_verifier, code_challenge):
            raise PKCEVerificationFailedError
    elif method == "S256":
        computed = compute_s256_challenge(code_verifier)
        if not hmac.compare_digest(computed, code_challenge):
            raise PKCEVerificationFailedError
    else:
        raise PKCEVerificationFailedError


def compute_s256_challenge(code_verifier: str) -> str:
    """Compute S256 code challenge from verifier.

    Args:
        code_verifier: The code verifier string.

    Returns:
        Base64url-encoded SHA-256 hash of the verifier.
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


__all__ = [
    "compute_s256_challenge",
    "verify_pkce",
]
