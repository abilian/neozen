"""Event bus for authentication events."""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import inspect
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

from .types import AuthEvent

logger = logging.getLogger(__name__)

# Type aliases for event handlers
AsyncEventHandler = Callable[[AuthEvent], Awaitable[None]]
SyncEventHandler = Callable[[AuthEvent], None]
EventHandler = AsyncEventHandler | SyncEventHandler


class EventBus:
    """Central event bus for authentication events.

    The event bus allows components to subscribe to authentication events
    and receive notifications when events occur. Supports both sync and
    async handlers, wildcard patterns, and background emission.

    Example:
        bus = EventBus()

        # Subscribe to specific event
        async def on_login(event: AuthEvent) -> None:
            print(f"User {event.subject_id} logged in")

        bus.subscribe("login.success", on_login)

        # Subscribe to all login events
        bus.subscribe("login.*", on_login)

        # Emit event
        await bus.emit(AuthEvent(
            event_type="login.success",
            timestamp=datetime.now(UTC),
            subject_id="user123",
        ))
    """

    def __init__(self) -> None:
        """Initialize the event bus."""
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._background_tasks: set[asyncio.Task[None]] = set()

    def subscribe(
        self,
        event_pattern: str,
        handler: EventHandler,
    ) -> None:
        """Subscribe to events matching a pattern.

        Patterns support wildcards:
        - "login.*" matches login.success, login.failed
        - "*.created" matches subject.created, session.created
        - "*" matches all events

        Args:
            event_pattern: Pattern to match events against.
            handler: Function to call when matching event occurs.
                Can be sync or async.
        """
        self._handlers[event_pattern].append(handler)

    def unsubscribe(
        self,
        event_pattern: str,
        handler: EventHandler,
    ) -> None:
        """Remove a handler subscription.

        Args:
            event_pattern: The pattern the handler was subscribed to.
            handler: The handler to remove.
        """
        if event_pattern in self._handlers:
            with contextlib.suppress(ValueError):
                self._handlers[event_pattern].remove(handler)

    def unsubscribe_all(self, event_pattern: str) -> None:
        """Remove all handlers for a pattern.

        Args:
            event_pattern: The pattern to clear handlers for.
        """
        self._handlers.pop(event_pattern, None)

    def clear(self) -> None:
        """Remove all subscriptions."""
        self._handlers.clear()

    async def emit(self, event: AuthEvent) -> None:
        """Emit an event to all matching handlers.

        Handlers are called in subscription order. Async handlers are
        awaited, sync handlers are called directly.

        Args:
            event: The event to emit.

        Note:
            Exceptions in handlers are logged but do not prevent
            other handlers from being called.
        """
        handlers = self._get_matching_handlers(event.event_type)

        for handler in handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception:
                logger.exception(
                    "Error in event handler for %s",
                    event.event_type,
                )

    def emit_sync(self, event: AuthEvent) -> None:
        """Emit an event synchronously.

        Only calls sync handlers. Async handlers are skipped with a warning.
        Use this when you need to emit from synchronous code.

        Args:
            event: The event to emit.
        """
        handlers = self._get_matching_handlers(event.event_type)

        for handler in handlers:
            if inspect.iscoroutinefunction(handler):
                logger.warning(
                    "Skipping async handler in sync emit for %s",
                    event.event_type,
                )
                continue

            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Error in sync event handler for %s",
                    event.event_type,
                )

    def emit_background(self, event: AuthEvent) -> None:
        """Schedule event emission as a background task.

        The event is emitted asynchronously without blocking the caller.
        Useful for non-critical handlers like logging or analytics.

        Args:
            event: The event to emit.
        """
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._emit_background(event))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        except RuntimeError:
            # No running event loop, emit synchronously
            self.emit_sync(event)

    async def _emit_background(self, event: AuthEvent) -> None:
        """Internal background emission handler."""
        try:
            await self.emit(event)
        except Exception:
            logger.exception(
                "Error in background event emission for %s",
                event.event_type,
            )

    def _get_matching_handlers(self, event_type: str) -> list[EventHandler]:
        """Get all handlers that match an event type.

        Args:
            event_type: The event type to match.

        Returns:
            List of handlers matching the event type.
        """
        handlers: list[EventHandler] = []

        for pattern, pattern_handlers in self._handlers.items():
            if self._matches_pattern(pattern, event_type):
                handlers.extend(pattern_handlers)

        return handlers

    @staticmethod
    def _matches_pattern(pattern: str, event_type: str) -> bool:
        """Check if an event type matches a pattern.

        Args:
            pattern: The pattern to match against.
            event_type: The event type to check.

        Returns:
            True if the event type matches the pattern.
        """
        # Direct match
        if pattern == event_type:
            return True

        # Wildcard match using fnmatch
        return fnmatch.fnmatch(event_type, pattern)

    async def wait_for_background_tasks(
        self,
        max_wait: float | None = None,
    ) -> None:
        """Wait for all background tasks to complete.

        Useful for testing or graceful shutdown.

        Args:
            max_wait: Maximum time to wait in seconds. None for no timeout.
        """
        if not self._background_tasks:
            return

        await asyncio.wait(
            self._background_tasks,
            timeout=max_wait,
        )

    @property
    def handler_count(self) -> int:
        """Total number of registered handlers."""
        return sum(len(handlers) for handlers in self._handlers.values())

    @property
    def pattern_count(self) -> int:
        """Number of unique patterns with handlers."""
        return len(self._handlers)
