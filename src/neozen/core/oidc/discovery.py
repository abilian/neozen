"""OIDC Provider discovery metadata (RFC 8414, OIDC Discovery 1.0)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class OIDCProviderMetadata:
    """OpenID Provider Metadata returned at /.well-known/openid-configuration.

    Spec: https://openid.net/specs/openid-connect-discovery-1_0.html
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str

    # Optional endpoints
    registration_endpoint: str | None = None
    introspection_endpoint: str | None = None
    revocation_endpoint: str | None = None
    end_session_endpoint: str | None = None

    # Supported scopes (default: standard OIDC scopes)
    scopes_supported: list[str] = field(
        default_factory=lambda: [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
        ]
    )

    # Response types (OIDC Core 1.0 Section 3)
    response_types_supported: list[str] = field(default_factory=lambda: ["code"])

    response_modes_supported: list[str] = field(
        default_factory=lambda: ["query", "fragment"]
    )

    grant_types_supported: list[str] = field(
        default_factory=lambda: [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ]
    )

    subject_types_supported: list[str] = field(default_factory=lambda: ["public"])

    id_token_signing_alg_values_supported: list[str] = field(
        default_factory=lambda: ["RS256"]
    )

    token_endpoint_auth_methods_supported: list[str] = field(
        default_factory=lambda: [
            "client_secret_basic",
            "client_secret_post",
        ]
    )

    claims_supported: list[str] = field(
        default_factory=lambda: [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "email",
            "email_verified",
            "picture",
            "locale",
            "updated_at",
        ]
    )

    code_challenge_methods_supported: list[str] = field(
        default_factory=lambda: ["S256"]
    )

    # OIDC Core 1.0 Section 5.5 (claims parameter)
    claims_parameter_supported: bool = False
    request_parameter_supported: bool = False
    request_uri_parameter_supported: bool = False
    require_request_uri_registration: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary (omits None fields)."""
        result: dict[str, Any] = {}
        for key, value in self.__dict__.items():
            if value is None:
                continue
            result[key] = value
        return result


def build_metadata_from_base_url(
    issuer: str,
    base_url: str,
    *,
    include_registration: bool = False,
) -> OIDCProviderMetadata:
    """Convenience: build provider metadata from a base URL.

    Endpoints follow NeoZen's standard paths:
    - /oauth/authorize
    - /oauth/token
    - /oauth/introspect
    - /oauth/revoke
    - /userinfo
    - /.well-known/jwks.json
    """
    base = base_url.rstrip("/")
    return OIDCProviderMetadata(
        issuer=issuer,
        authorization_endpoint=f"{base}/oauth/authorize",
        token_endpoint=f"{base}/oauth/token",
        userinfo_endpoint=f"{base}/userinfo",
        jwks_uri=f"{base}/.well-known/jwks.json",
        introspection_endpoint=f"{base}/oauth/introspect",
        revocation_endpoint=f"{base}/oauth/revoke",
        registration_endpoint=f"{base}/oauth/register"
        if include_registration
        else None,
    )


__all__ = [
    "OIDCProviderMetadata",
    "build_metadata_from_base_url",
]
