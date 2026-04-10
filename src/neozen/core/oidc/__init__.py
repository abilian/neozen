"""OpenID Connect 1.0 Provider implementation for NeoZen.

This package builds on top of the OAuth 2.1 server (`neozen.core.oauth`)
to provide a full OIDC Provider:

- Key management (JWK/JWKS) for ID token signing
- ID Token generation (signed JWT)
- Discovery endpoint metadata (RFC 8414)
- UserInfo endpoint (OIDC Core 1.0 Section 5.3)
- Scope-to-claims mapping

OIDC requires the `oidc` extra: `uv add "neozen[oidc]"`
"""

from __future__ import annotations

from neozen.core.oidc.claims import (
    SCOPE_CLAIMS,
    ClaimsProvider,
    DefaultClaimsProvider,
    SubjectClaims,
)
from neozen.core.oidc.consent import (
    ConsentRecord,
    ConsentRepository,
    ConsentService,
)
from neozen.core.oidc.discovery import OIDCProviderMetadata
from neozen.core.oidc.id_token import (
    IDTokenClaims,
    IDTokenGenerator,
    IDTokenVerifier,
)
from neozen.core.oidc.keys import (
    JWK,
    JWKS,
    InMemoryKeyManager,
    KeyManager,
    SigningKey,
)

__all__ = [
    "JWK",
    "JWKS",
    "ClaimsProvider",
    "ConsentRecord",
    "ConsentRepository",
    "ConsentService",
    "DefaultClaimsProvider",
    "IDTokenClaims",
    "IDTokenGenerator",
    "IDTokenVerifier",
    "InMemoryKeyManager",
    "KeyManager",
    "OIDCProviderMetadata",
    "SCOPE_CLAIMS",
    "SigningKey",
    "SubjectClaims",
]
