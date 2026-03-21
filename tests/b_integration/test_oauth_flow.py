"""Integration tests for OAuth 2.1 authorization code flow.

Tests the full OAuth flow with real SQLAlchemy repositories.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from neozen.core.oauth.services import OAuthTokenService
from neozen.storage.sqlalchemy import Base
from neozen.storage.sqlalchemy.oauth_models import (
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthRefreshToken,
)
from neozen.storage.sqlalchemy.oauth_repositories import (
    OAuthAccessTokenRepository,
    OAuthAuthorizationCodeRepository,
    OAuthClientRepository,
    OAuthGrantRepository,
    OAuthRefreshTokenRepository,
)

TOKEN_HASH_KEY = "test_secret_key_for_oauth_flow"


@pytest.fixture
async def engine(tmp_path):
    """Create a fresh database engine for each test."""
    from sqlalchemy.pool import NullPool

    db_path = tmp_path / "oauth_test.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(db_url, poolclass=NullPool)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def session(engine):
    """Create a database session for testing."""
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        yield session


@pytest.fixture
def client_repo(session: AsyncSession) -> OAuthClientRepository:
    return OAuthClientRepository(session=session)


@pytest.fixture
def grant_repo(session: AsyncSession) -> OAuthGrantRepository:
    return OAuthGrantRepository(session=session)


@pytest.fixture
def auth_code_repo(session: AsyncSession) -> OAuthAuthorizationCodeRepository:
    return OAuthAuthorizationCodeRepository(session=session)


@pytest.fixture
def access_token_repo(session: AsyncSession) -> OAuthAccessTokenRepository:
    return OAuthAccessTokenRepository(session=session)


@pytest.fixture
def refresh_token_repo(session: AsyncSession) -> OAuthRefreshTokenRepository:
    return OAuthRefreshTokenRepository(session=session)


@pytest.fixture
def token_service(
    client_repo: OAuthClientRepository,
    auth_code_repo: OAuthAuthorizationCodeRepository,
    access_token_repo: OAuthAccessTokenRepository,
    refresh_token_repo: OAuthRefreshTokenRepository,
) -> OAuthTokenService:
    return OAuthTokenService(
        client_repository=client_repo,
        authorization_code_repository=auth_code_repo,
        access_token_repository=access_token_repo,
        refresh_token_repository=refresh_token_repo,
        token_hash_key=TOKEN_HASH_KEY,
    )


@pytest.mark.anyio
class TestOAuthAuthorizationCodeFlow:
    """Integration tests for the authorization code grant flow."""

    async def test_full_authorization_code_flow(
        self,
        session: AsyncSession,
        client_repo: OAuthClientRepository,
        auth_code_repo: OAuthAuthorizationCodeRepository,
        token_service: OAuthTokenService,
    ) -> None:
        """Test the complete authorization code flow from code to tokens."""
        # 1. Create an OAuth client
        client = OAuthClient()
        client.client_id = "test_client_app"
        await client_repo.add(client)
        await session.commit()

        # 2. Simulate authorization code creation (normally done by AuthorizationCodeGrant)
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        # For plain PKCE, challenge equals verifier
        code_challenge = code_verifier

        auth_code = OAuthAuthorizationCode()
        auth_code.code = "test_auth_code_hash"
        auth_code.client_id = "test_client_app"
        auth_code.subject_id = "user_123"
        auth_code.expires_at = datetime.now(UTC) + timedelta(minutes=10)
        auth_code.response_type = "code"
        auth_code.redirect_uri = "https://example.com/callback"
        auth_code.scope = "read write"
        auth_code.code_challenge = code_challenge
        auth_code.code_challenge_method = "plain"
        await auth_code_repo.add(auth_code)
        await session.commit()

        # 3. Validate the authorization code
        validated_code = await token_service.validate_authorization_code(
            code="test_auth_code_hash",
            client_id="test_client_app",
            redirect_uri="https://example.com/callback",
            code_verifier=code_verifier,
        )

        assert validated_code.client_id == "test_client_app"
        assert validated_code.subject_id == "user_123"
        assert validated_code.scope == "read write"

        # 4. Exchange the code for tokens
        token_pair = await token_service.exchange_authorization_code(
            validated_code, client
        )
        await session.commit()

        assert token_pair.access_token.startswith("nz_at_")
        assert token_pair.refresh_token.startswith("nz_rt_")
        assert token_pair.scope == "read write"

    async def test_refresh_token_flow(
        self,
        session: AsyncSession,
        client_repo: OAuthClientRepository,
        auth_code_repo: OAuthAuthorizationCodeRepository,
        refresh_token_repo: OAuthRefreshTokenRepository,
        token_service: OAuthTokenService,
    ) -> None:
        """Test refreshing an access token."""
        # 1. Create OAuth client
        client = OAuthClient()
        client.client_id = "refresh_test_client"
        await client_repo.add(client)
        await session.commit()

        # 2. Create a valid authorization code and exchange it
        code_verifier = "test_verifier_43_chars_xxxxxxxxxxxxxxxxxxx"
        auth_code = OAuthAuthorizationCode()
        auth_code.code = "refresh_test_code"
        auth_code.client_id = "refresh_test_client"
        auth_code.subject_id = "user_456"
        auth_code.expires_at = datetime.now(UTC) + timedelta(minutes=10)
        auth_code.response_type = "code"
        auth_code.redirect_uri = None
        auth_code.scope = "read write"
        auth_code.code_challenge = code_verifier
        auth_code.code_challenge_method = "plain"
        await auth_code_repo.add(auth_code)
        await session.commit()

        validated_code = await token_service.validate_authorization_code(
            code="refresh_test_code",
            client_id="refresh_test_client",
            redirect_uri=None,
            code_verifier=code_verifier,
        )
        token_pair = await token_service.exchange_authorization_code(
            validated_code, client
        )
        await session.commit()

        # 3. Use the refresh token to get a new access token
        stored_refresh = await token_service.validate_refresh_token(
            refresh_token=token_pair.refresh_token,
            client_id="refresh_test_client",
        )

        validated_scope = token_service.validate_scope_downgrade(
            requested_scope=None,
            original_scope=stored_refresh.scope,
        )

        result = await token_service.refresh_access_token(
            stored_refresh, client, validated_scope
        )
        await session.commit()

        # Verify new tokens were created
        assert result.access_token.startswith("nz_at_")
        assert result.new_refresh_token is not None  # rotation enabled by default
        assert result.new_refresh_token.startswith("nz_rt_")
        assert result.scope == "read write"

        # Old refresh token should be revoked
        assert stored_refresh.revoked_at is not None

    async def test_scope_downgrade_on_refresh(
        self,
        session: AsyncSession,
        client_repo: OAuthClientRepository,
        auth_code_repo: OAuthAuthorizationCodeRepository,
        token_service: OAuthTokenService,
    ) -> None:
        """Test requesting a reduced scope on refresh."""
        # Setup
        client = OAuthClient()
        client.client_id = "scope_test_client"
        await client_repo.add(client)

        code_verifier = "scope_verifier_43_chars_xxxxxxxxxxxxxxxxxxxxx"
        auth_code = OAuthAuthorizationCode()
        auth_code.code = "scope_test_code"
        auth_code.client_id = "scope_test_client"
        auth_code.subject_id = "user_789"
        auth_code.expires_at = datetime.now(UTC) + timedelta(minutes=10)
        auth_code.response_type = "code"
        auth_code.redirect_uri = None
        auth_code.scope = "read write delete"
        auth_code.code_challenge = code_verifier
        auth_code.code_challenge_method = "plain"
        await auth_code_repo.add(auth_code)
        await session.commit()

        # Get initial tokens with full scope
        validated = await token_service.validate_authorization_code(
            code="scope_test_code",
            client_id="scope_test_client",
            redirect_uri=None,
            code_verifier=code_verifier,
        )
        token_pair = await token_service.exchange_authorization_code(validated, client)
        await session.commit()

        assert token_pair.scope == "read write delete"

        # Refresh with reduced scope
        stored_refresh = await token_service.validate_refresh_token(
            token_pair.refresh_token, "scope_test_client"
        )

        # Request only "read" scope
        validated_scope = token_service.validate_scope_downgrade(
            requested_scope="read",
            original_scope=stored_refresh.scope,
        )

        result = await token_service.refresh_access_token(
            stored_refresh, client, validated_scope
        )
        await session.commit()

        assert result.scope == "read"


@pytest.mark.anyio
class TestOAuthErrorHandling:
    """Integration tests for OAuth error scenarios."""

    async def test_expired_authorization_code(
        self,
        session: AsyncSession,
        client_repo: OAuthClientRepository,
        auth_code_repo: OAuthAuthorizationCodeRepository,
        token_service: OAuthTokenService,
    ) -> None:
        """Test that expired authorization codes are rejected."""
        from neozen.core.oauth.exceptions import AuthorizationCodeExpiredError

        client = OAuthClient()
        client.client_id = "expired_test_client"
        await client_repo.add(client)

        code_verifier = "expired_verifier_43_chars_xxxxxxxxxxxxxxxxx"
        auth_code = OAuthAuthorizationCode()
        auth_code.code = "expired_code"
        auth_code.client_id = "expired_test_client"
        auth_code.subject_id = "user_expired"
        auth_code.expires_at = datetime.now(UTC) - timedelta(minutes=1)  # expired
        auth_code.response_type = "code"
        auth_code.redirect_uri = None
        auth_code.scope = "read"
        auth_code.code_challenge = code_verifier
        auth_code.code_challenge_method = "plain"
        await auth_code_repo.add(auth_code)
        await session.commit()

        with pytest.raises(AuthorizationCodeExpiredError):
            await token_service.validate_authorization_code(
                code="expired_code",
                client_id="expired_test_client",
                redirect_uri=None,
                code_verifier=code_verifier,
            )

    async def test_revoked_refresh_token(
        self,
        session: AsyncSession,
        client_repo: OAuthClientRepository,
        refresh_token_repo: OAuthRefreshTokenRepository,
        token_service: OAuthTokenService,
    ) -> None:
        """Test that revoked refresh tokens are rejected."""
        from neozen.core.crypto import get_token_hash
        from neozen.core.oauth.exceptions import RefreshTokenRevokedError

        client = OAuthClient()
        client.client_id = "revoked_test_client"
        await client_repo.add(client)

        # Create a revoked refresh token
        raw_token = "nz_rt_revoked_token_value"
        token_hash = get_token_hash(raw_token, key=TOKEN_HASH_KEY)

        refresh_token = OAuthRefreshToken()
        refresh_token.token_hash = token_hash
        refresh_token.client_id = "revoked_test_client"
        refresh_token.subject_id = "user_revoked"
        refresh_token.scope = "read"
        refresh_token.expires_at = datetime.now(UTC) + timedelta(days=30)
        refresh_token.created_at = datetime.now(UTC)
        refresh_token.revoked_at = datetime.now(UTC)  # revoked
        refresh_token.access_token_hash = None
        await refresh_token_repo.add(refresh_token)
        await session.commit()

        with pytest.raises(RefreshTokenRevokedError):
            await token_service.validate_refresh_token(
                refresh_token=raw_token,
                client_id="revoked_test_client",
            )

    async def test_pkce_verification_failure(
        self,
        session: AsyncSession,
        client_repo: OAuthClientRepository,
        auth_code_repo: OAuthAuthorizationCodeRepository,
        token_service: OAuthTokenService,
    ) -> None:
        """Test that PKCE verification catches invalid verifiers."""
        from neozen.core.oauth.exceptions import PKCEVerificationFailedError

        client = OAuthClient()
        client.client_id = "pkce_test_client"
        await client_repo.add(client)

        correct_verifier = "correct_verifier_43_chars_xxxxxxxxxxxxxxxxx"
        auth_code = OAuthAuthorizationCode()
        auth_code.code = "pkce_test_code"
        auth_code.client_id = "pkce_test_client"
        auth_code.subject_id = "user_pkce"
        auth_code.expires_at = datetime.now(UTC) + timedelta(minutes=10)
        auth_code.response_type = "code"
        auth_code.redirect_uri = None
        auth_code.scope = "read"
        auth_code.code_challenge = correct_verifier
        auth_code.code_challenge_method = "plain"
        await auth_code_repo.add(auth_code)
        await session.commit()

        wrong_verifier = "wrong_verifier_43_chars_xxxxxxxxxxxxxxxxxxxx"
        with pytest.raises(PKCEVerificationFailedError):
            await token_service.validate_authorization_code(
                code="pkce_test_code",
                client_id="pkce_test_client",
                redirect_uri=None,
                code_verifier=wrong_verifier,
            )
