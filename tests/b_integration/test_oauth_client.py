"""Integration tests for OAuth client with SQLAlchemy storage.

Tests the OAuthClientService with real database storage for state and accounts.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from neozen.core.oauth_client.exceptions import (
    OAuthProviderNotFoundError,
    OAuthStateError,
)
from neozen.core.oauth_client.providers.google import create_google_config
from neozen.core.oauth_client.service import OAuthClientService
from neozen.core.repository import DoesNotExist
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.models import Subject
from neozen.storage.sqlalchemy.repositories import (
    OAuthStateRepository,
    SocialAccountRepository,
    SubjectRepository,
)


@pytest.fixture
async def async_engine():
    """Create async SQLite engine for tests."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def session(async_engine):
    """Create async session for tests."""
    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_maker() as session:
        yield session


@pytest.fixture
def subject_repo(session: AsyncSession) -> SubjectRepository:
    """Create subject repository."""
    return SubjectRepository(session=session)


@pytest.fixture
def state_repo(session: AsyncSession) -> OAuthStateRepository:
    """Create OAuth state repository."""
    return OAuthStateRepository(session=session)


@pytest.fixture
def social_account_repo(session: AsyncSession) -> SocialAccountRepository:
    """Create social account repository."""
    return SocialAccountRepository(session=session)


@pytest.fixture
def mock_http_client():
    """Create a mock HTTP client."""
    return AsyncMock()


@pytest.fixture
def oauth_service(
    state_repo: OAuthStateRepository,
    social_account_repo: SocialAccountRepository,
    mock_http_client,
) -> OAuthClientService:
    """Create OAuth client service."""
    service = OAuthClientService(
        state_repository=state_repo,
        social_account_repository=social_account_repo,
        http_client=mock_http_client,
        id_generator=lambda: secrets.token_hex(16),
    )
    # Register Google provider
    google_config = create_google_config(
        client_id="test-client-id",
        client_secret="test-client-secret",
    )
    service.register_provider(google_config)
    return service


@pytest.fixture
async def subject(subject_repo: SubjectRepository) -> Subject:
    """Create a test subject."""
    return await subject_repo.create(
        id=secrets.token_hex(16),
        email="test@example.com",
        hashed_password=None,
        is_active=True,
        is_verified=False,
    )


@pytest.mark.anyio
class TestOAuthProviderRegistration:
    """Tests for OAuth provider registration."""

    async def test_register_provider(
        self,
        state_repo: OAuthStateRepository,
        social_account_repo: SocialAccountRepository,
        mock_http_client,
    ) -> None:
        """Test registering an OAuth provider."""
        service = OAuthClientService(
            state_repository=state_repo,
            social_account_repository=social_account_repo,
            http_client=mock_http_client,
        )

        google_config = create_google_config("client-id", "client-secret")
        service.register_provider(google_config)

        # Should be able to get the provider
        provider = service.get_provider("google")
        assert provider is not None

    async def test_get_nonexistent_provider_raises(
        self,
        state_repo: OAuthStateRepository,
        social_account_repo: SocialAccountRepository,
        mock_http_client,
    ) -> None:
        """Test that getting nonexistent provider raises error."""
        service = OAuthClientService(
            state_repository=state_repo,
            social_account_repository=social_account_repo,
            http_client=mock_http_client,
        )

        with pytest.raises(OAuthProviderNotFoundError):
            service.get_provider("nonexistent")


@pytest.mark.anyio
class TestBeginAuthorization:
    """Tests for beginning OAuth authorization flow."""

    async def test_begin_authorization_returns_url(
        self, oauth_service: OAuthClientService
    ) -> None:
        """Test that begin_authorization returns authorization URL."""
        result = await oauth_service.begin_authorization(
            provider_id="google",
            redirect_uri="http://localhost/callback",
        )

        assert result.authorization_url is not None
        assert "accounts.google.com" in result.authorization_url
        assert result.state is not None

    async def test_begin_authorization_stores_state(
        self,
        oauth_service: OAuthClientService,
        state_repo: OAuthStateRepository,
    ) -> None:
        """Test that authorization state is stored in database."""
        result = await oauth_service.begin_authorization(
            provider_id="google",
            redirect_uri="http://localhost/callback",
        )

        stored_state = await state_repo.get_one_by(state=result.state)
        assert stored_state is not None
        assert stored_state.provider_id == "google"
        assert stored_state.redirect_uri == "http://localhost/callback"
        assert stored_state.code_verifier is not None  # PKCE

    async def test_begin_authorization_with_existing_subject(
        self,
        oauth_service: OAuthClientService,
        state_repo: OAuthStateRepository,
        subject: Subject,
    ) -> None:
        """Test beginning authorization for account linking."""
        result = await oauth_service.begin_authorization(
            provider_id="google",
            redirect_uri="http://localhost/callback",
            existing_subject_id=subject.id,
        )

        stored_state = await state_repo.get_one_by(state=result.state)
        assert stored_state.existing_subject_id == subject.id

    async def test_begin_authorization_unknown_provider_raises(
        self, oauth_service: OAuthClientService
    ) -> None:
        """Test that unknown provider raises error."""
        with pytest.raises(OAuthProviderNotFoundError):
            await oauth_service.begin_authorization(
                provider_id="unknown",
                redirect_uri="http://localhost/callback",
            )


@pytest.mark.anyio
class TestHandleCallback:
    """Tests for handling OAuth callback."""

    async def test_handle_callback_invalid_state_raises(
        self, oauth_service: OAuthClientService
    ) -> None:
        """Test that invalid state raises error."""
        with pytest.raises(OAuthStateError):
            await oauth_service.handle_callback(
                provider_id="google",
                code="auth-code-123",
                state="invalid-state",
            )


@pytest.mark.anyio
class TestStateRepository:
    """Tests for OAuth state repository operations."""

    async def test_state_stored_with_pkce(
        self,
        state_repo: OAuthStateRepository,
    ) -> None:
        """Test that state is stored with PKCE verifier."""
        created_state = await state_repo.create(
            state="test-state",
            code_verifier="test-verifier-123",
            redirect_uri="http://localhost/callback",
            provider_id="google",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        # Verify created state has correct values
        assert created_state.code_verifier == "test-verifier-123"
        assert created_state.provider_id == "google"

        # Also verify retrieval works
        retrieved = await state_repo.get_one_by(state="test-state")
        assert retrieved.code_verifier == "test-verifier-123"
        assert retrieved.provider_id == "google"

    async def test_state_deleted(
        self,
        state_repo: OAuthStateRepository,
    ) -> None:
        """Test that state can be deleted."""
        state = await state_repo.create(
            state="to-delete",
            code_verifier="verifier",
            redirect_uri="http://localhost/callback",
            provider_id="google",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        await state_repo.delete(state)

        with pytest.raises(DoesNotExist):
            await state_repo.get_one_by(state="to-delete")


@pytest.mark.anyio
class TestSocialAccountRepository:
    """Tests for social account repository operations."""

    async def test_social_account_created(
        self,
        social_account_repo: SocialAccountRepository,
        subject: Subject,
    ) -> None:
        """Test that social account can be created."""
        account = await social_account_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            provider_id="google",
            provider_user_id="google-123",
            email="user@gmail.com",
            display_name="Test User",
            access_token="access-token",
            refresh_token="refresh-token",
            token_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        # Verify created account has correct values
        assert account.provider_user_id == "google-123"
        assert account.email == "user@gmail.com"

        # Also verify retrieval works
        retrieved = await social_account_repo.get_one_by(
            subject_id=subject.id, provider_id="google"
        )
        assert retrieved.provider_user_id == "google-123"
        assert retrieved.email == "user@gmail.com"

    async def test_social_accounts_by_subject(
        self,
        social_account_repo: SocialAccountRepository,
        subject: Subject,
    ) -> None:
        """Test getting all social accounts for a subject."""
        # Create multiple accounts
        await social_account_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            provider_id="google",
            provider_user_id="google-123",
        )
        await social_account_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            provider_id="github",
            provider_user_id="github-456",
        )

        accounts = await social_account_repo.get_many_by(subject_id=subject.id)
        assert len(accounts) == 2

    async def test_social_account_updated(
        self,
        social_account_repo: SocialAccountRepository,
        subject: Subject,
    ) -> None:
        """Test that social account can be updated."""
        account = await social_account_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            provider_id="google",
            provider_user_id="google-123",
            access_token="old-token",
        )

        updated = await social_account_repo.update_obj(
            account,
            access_token="new-token",
            email="updated@gmail.com",
        )

        assert updated.access_token == "new-token"
        assert updated.email == "updated@gmail.com"

    async def test_social_account_deleted(
        self,
        social_account_repo: SocialAccountRepository,
        subject: Subject,
    ) -> None:
        """Test that social account can be deleted."""
        account = await social_account_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            provider_id="google",
            provider_user_id="google-123",
        )

        await social_account_repo.delete(account)

        accounts = await social_account_repo.get_many_by(subject_id=subject.id)
        assert len(accounts) == 0

    async def test_social_accounts_isolated_by_subject(
        self,
        social_account_repo: SocialAccountRepository,
        subject_repo: SubjectRepository,
        subject: Subject,
    ) -> None:
        """Test that social accounts are isolated per subject."""
        # Create another subject
        other_subject = await subject_repo.create(
            id=secrets.token_hex(16),
            email="other@example.com",
            hashed_password=None,
            is_active=True,
            is_verified=False,
        )

        # Create accounts for both
        await social_account_repo.create(
            id=secrets.token_hex(16),
            subject_id=subject.id,
            provider_id="google",
            provider_user_id="google-111",
        )
        await social_account_repo.create(
            id=secrets.token_hex(16),
            subject_id=other_subject.id,
            provider_id="google",
            provider_user_id="google-222",
        )

        # Each subject should only see their own
        accounts1 = await social_account_repo.get_many_by(subject_id=subject.id)
        accounts2 = await social_account_repo.get_many_by(subject_id=other_subject.id)

        assert len(accounts1) == 1
        assert accounts1[0].provider_user_id == "google-111"

        assert len(accounts2) == 1
        assert accounts2[0].provider_user_id == "google-222"
