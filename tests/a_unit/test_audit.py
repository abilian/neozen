"""Unit tests for audit logging."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from neozen.core.audit.logger import AuditLogger
from neozen.core.audit.store import InMemoryAuditLogStore
from neozen.core.audit.types import AuditActions, AuditLogEntry, AuditOutcome


@pytest.fixture
def store() -> InMemoryAuditLogStore:
    """Create an in-memory audit log store."""
    return InMemoryAuditLogStore()


@pytest.fixture
def logger(store: InMemoryAuditLogStore) -> AuditLogger:
    """Create an audit logger."""
    return AuditLogger(store)


class TestAuditActions:
    """Tests for AuditActions constants."""

    def test_login_action(self) -> None:
        """Test login action constant."""
        assert AuditActions.LOGIN == "login"

    def test_password_change_action(self) -> None:
        """Test password change action constant."""
        assert AuditActions.PASSWORD_CHANGE == "password_change"

    def test_token_issue_action(self) -> None:
        """Test token issue action constant."""
        assert AuditActions.TOKEN_ISSUE == "token_issue"


class TestAuditOutcome:
    """Tests for AuditOutcome constants."""

    def test_success(self) -> None:
        """Test success outcome."""
        assert AuditOutcome.SUCCESS == "success"

    def test_failure(self) -> None:
        """Test failure outcome."""
        assert AuditOutcome.FAILURE == "failure"

    def test_error(self) -> None:
        """Test error outcome."""
        assert AuditOutcome.ERROR == "error"


class TestAuditLogEntry:
    """Tests for AuditLogEntry."""

    def test_create_entry(self) -> None:
        """Test creating an audit log entry."""
        now = datetime.now(UTC)
        entry = AuditLogEntry(
            id="entry1",
            timestamp=now,
            event_type="auth",
            action=AuditActions.LOGIN,
            outcome=AuditOutcome.SUCCESS,
            subject_id="user123",
        )

        assert entry.id == "entry1"
        assert entry.timestamp == now
        assert entry.event_type == "auth"
        assert entry.action == "login"
        assert entry.outcome == "success"
        assert entry.subject_id == "user123"

    def test_entry_defaults(self) -> None:
        """Test audit log entry defaults."""
        entry = AuditLogEntry(
            id="entry1",
            timestamp=datetime.now(UTC),
            event_type="auth",
            action="login",
            outcome="success",
        )

        assert entry.subject_id is None
        assert entry.actor_id is None
        assert entry.ip_address is None
        assert entry.user_agent is None
        assert entry.resource_type is None
        assert entry.resource_id is None
        assert entry.details == {}
        assert entry.request_id is None


class TestInMemoryAuditLogStore:
    """Tests for InMemoryAuditLogStore."""

    @pytest.mark.anyio
    async def test_append_and_get(self, store: InMemoryAuditLogStore) -> None:
        """Test appending and getting an entry."""
        entry = AuditLogEntry(
            id="entry1",
            timestamp=datetime.now(UTC),
            event_type="auth",
            action="login",
            outcome="success",
            subject_id="user123",
        )

        await store.append(entry)
        result = await store.get_by_id("entry1")

        assert result is not None
        assert result.id == "entry1"
        assert result.subject_id == "user123"

    @pytest.mark.anyio
    async def test_get_nonexistent(self, store: InMemoryAuditLogStore) -> None:
        """Test getting nonexistent entry."""
        result = await store.get_by_id("nonexistent")
        assert result is None

    @pytest.mark.anyio
    async def test_query_by_subject(self, store: InMemoryAuditLogStore) -> None:
        """Test querying by subject ID."""
        now = datetime.now(UTC)

        entry1 = AuditLogEntry(
            id="1",
            timestamp=now,
            event_type="auth",
            action="login",
            outcome="success",
            subject_id="user1",
        )
        entry2 = AuditLogEntry(
            id="2",
            timestamp=now,
            event_type="auth",
            action="login",
            outcome="success",
            subject_id="user2",
        )
        entry3 = AuditLogEntry(
            id="3",
            timestamp=now,
            event_type="auth",
            action="logout",
            outcome="success",
            subject_id="user1",
        )

        await store.append(entry1)
        await store.append(entry2)
        await store.append(entry3)

        results = await store.query(subject_id="user1")

        assert len(results) == 2
        assert all(e.subject_id == "user1" for e in results)

    @pytest.mark.anyio
    async def test_query_by_action(self, store: InMemoryAuditLogStore) -> None:
        """Test querying by action."""
        now = datetime.now(UTC)

        await store.append(
            AuditLogEntry(
                id="1",
                timestamp=now,
                event_type="auth",
                action="login",
                outcome="success",
            )
        )
        await store.append(
            AuditLogEntry(
                id="2",
                timestamp=now,
                event_type="auth",
                action="logout",
                outcome="success",
            )
        )

        results = await store.query(action="login")

        assert len(results) == 1
        assert results[0].action == "login"

    @pytest.mark.anyio
    async def test_query_by_time_range(self, store: InMemoryAuditLogStore) -> None:
        """Test querying by time range."""
        now = datetime.now(UTC)
        yesterday = now - timedelta(days=1)
        tomorrow = now + timedelta(days=1)

        await store.append(
            AuditLogEntry(
                id="1",
                timestamp=yesterday,
                event_type="auth",
                action="login",
                outcome="success",
            )
        )
        await store.append(
            AuditLogEntry(
                id="2",
                timestamp=now,
                event_type="auth",
                action="login",
                outcome="success",
            )
        )

        # Query for today only
        start = now - timedelta(hours=1)
        results = await store.query(start_time=start, end_time=tomorrow)

        assert len(results) == 1
        assert results[0].id == "2"

    @pytest.mark.anyio
    async def test_query_with_limit(self, store: InMemoryAuditLogStore) -> None:
        """Test query limit."""
        now = datetime.now(UTC)

        for i in range(10):
            await store.append(
                AuditLogEntry(
                    id=str(i),
                    timestamp=now + timedelta(seconds=i),
                    event_type="auth",
                    action="login",
                    outcome="success",
                )
            )

        results = await store.query(limit=3)
        assert len(results) == 3

    @pytest.mark.anyio
    async def test_query_with_offset(self, store: InMemoryAuditLogStore) -> None:
        """Test query offset."""
        now = datetime.now(UTC)

        for i in range(10):
            await store.append(
                AuditLogEntry(
                    id=str(i),
                    timestamp=now + timedelta(seconds=i),
                    event_type="auth",
                    action="login",
                    outcome="success",
                )
            )

        results = await store.query(limit=3, offset=3)
        assert len(results) == 3

    @pytest.mark.anyio
    async def test_count(self, store: InMemoryAuditLogStore) -> None:
        """Test counting entries."""
        now = datetime.now(UTC)

        for i in range(5):
            await store.append(
                AuditLogEntry(
                    id=str(i),
                    timestamp=now,
                    event_type="auth",
                    action="login",
                    outcome="success",
                )
            )

        count = await store.count()
        assert count == 5

    @pytest.mark.anyio
    async def test_count_with_filter(self, store: InMemoryAuditLogStore) -> None:
        """Test counting with filter."""
        now = datetime.now(UTC)

        await store.append(
            AuditLogEntry(
                id="1",
                timestamp=now,
                event_type="auth",
                action="login",
                outcome="success",
                subject_id="user1",
            )
        )
        await store.append(
            AuditLogEntry(
                id="2",
                timestamp=now,
                event_type="auth",
                action="login",
                outcome="success",
                subject_id="user2",
            )
        )
        await store.append(
            AuditLogEntry(
                id="3",
                timestamp=now,
                event_type="auth",
                action="logout",
                outcome="success",
                subject_id="user1",
            )
        )

        count = await store.count(subject_id="user1")
        assert count == 2

    @pytest.mark.anyio
    async def test_max_entries_limit(self) -> None:
        """Test max entries limit."""
        store = InMemoryAuditLogStore(max_entries=5)
        now = datetime.now(UTC)

        for i in range(10):
            await store.append(
                AuditLogEntry(
                    id=str(i),
                    timestamp=now,
                    event_type="auth",
                    action="login",
                    outcome="success",
                )
            )

        count = await store.count()
        assert count == 5


class TestAuditLogger:
    """Tests for AuditLogger."""

    @pytest.mark.anyio
    async def test_log_entry(self, logger: AuditLogger) -> None:
        """Test logging an entry."""
        entry = await logger.log(
            event_type="auth",
            action=AuditActions.LOGIN,
            outcome=AuditOutcome.SUCCESS,
            subject_id="user123",
            ip_address="192.168.1.1",
        )

        assert entry.id is not None
        assert entry.event_type == "auth"
        assert entry.action == "login"
        assert entry.outcome == "success"
        assert entry.subject_id == "user123"
        assert entry.ip_address == "192.168.1.1"

    @pytest.mark.anyio
    async def test_log_success_helper(self, logger: AuditLogger) -> None:
        """Test log_success helper."""
        entry = await logger.log_success(
            event_type="auth",
            action=AuditActions.LOGIN,
            subject_id="user123",
        )

        assert entry.outcome == AuditOutcome.SUCCESS

    @pytest.mark.anyio
    async def test_log_failure_helper(self, logger: AuditLogger) -> None:
        """Test log_failure helper."""
        entry = await logger.log_failure(
            event_type="auth",
            action=AuditActions.LOGIN_FAILED,
            subject_id="user123",
        )

        assert entry.outcome == AuditOutcome.FAILURE

    @pytest.mark.anyio
    async def test_log_error_helper(self, logger: AuditLogger) -> None:
        """Test log_error helper."""
        entry = await logger.log_error(
            event_type="auth",
            action=AuditActions.LOGIN,
            details={"error": "Database unavailable"},
        )

        assert entry.outcome == AuditOutcome.ERROR

    @pytest.mark.anyio
    async def test_log_with_details(self, logger: AuditLogger) -> None:
        """Test logging with details."""
        entry = await logger.log(
            event_type="oauth",
            action=AuditActions.TOKEN_ISSUE,
            outcome=AuditOutcome.SUCCESS,
            details={"grant_type": "authorization_code", "scopes": "read write"},
        )

        assert entry.details["grant_type"] == "authorization_code"
        assert entry.details["scopes"] == "read write"

    @pytest.mark.anyio
    async def test_log_with_resource(self, logger: AuditLogger) -> None:
        """Test logging with resource info."""
        entry = await logger.log(
            event_type="admin",
            action=AuditActions.ROLE_ASSIGN,
            outcome=AuditOutcome.SUCCESS,
            actor_id="admin1",
            subject_id="user123",
            resource_type="role",
            resource_id="admin_role",
        )

        assert entry.actor_id == "admin1"
        assert entry.resource_type == "role"
        assert entry.resource_id == "admin_role"

    @pytest.mark.anyio
    async def test_query(self, logger: AuditLogger) -> None:
        """Test querying logs."""
        await logger.log("auth", "login", "success", subject_id="user1")
        await logger.log("auth", "login", "success", subject_id="user2")
        await logger.log("auth", "logout", "success", subject_id="user1")

        results = await logger.query(subject_id="user1")

        assert len(results) == 2

    @pytest.mark.anyio
    async def test_count(self, logger: AuditLogger) -> None:
        """Test counting logs."""
        for _ in range(5):
            await logger.log("auth", "login", "success")

        count = await logger.count()
        assert count == 5

    @pytest.mark.anyio
    async def test_get_by_id(self, logger: AuditLogger) -> None:
        """Test getting log by ID."""
        entry = await logger.log("auth", "login", "success")
        result = await logger.get_by_id(entry.id)

        assert result is not None
        assert result.id == entry.id

    @pytest.mark.anyio
    async def test_custom_entry_id(self, logger: AuditLogger) -> None:
        """Test using custom entry ID."""
        entry = await logger.log(
            event_type="auth",
            action="login",
            outcome="success",
            entry_id="custom-id-123",
        )

        assert entry.id == "custom-id-123"

    @pytest.mark.anyio
    async def test_no_generate_id_requires_id(
        self,
        store: InMemoryAuditLogStore,
    ) -> None:
        """Test that generate_id=False requires entry_id."""
        logger = AuditLogger(store, generate_id=False)

        with pytest.raises(ValueError, match="entry_id is required"):
            await logger.log("auth", "login", "success")

    @pytest.mark.anyio
    async def test_request_id_tracking(self, logger: AuditLogger) -> None:
        """Test request ID for tracing."""
        entry = await logger.log(
            event_type="auth",
            action="login",
            outcome="success",
            request_id="req-12345",
        )

        assert entry.request_id == "req-12345"
