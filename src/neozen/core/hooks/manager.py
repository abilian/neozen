"""Hook manager for authentication flows."""

from __future__ import annotations

import logging
import operator
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

from .types import HookContext, HookResult

logger = logging.getLogger(__name__)

# Type alias for hook handlers
HookHandler = Callable[[HookContext], Awaitable[HookResult | None]]


class HookManager:
    """Manages hook registration and execution.

    The hook manager allows registering handlers for various hook points
    in the authentication flow. Handlers are executed in priority order.

    Example:
        manager = HookManager()

        # Register a pre-login hook
        async def check_ip_blocklist(ctx: HookContext) -> HookResult | None:
            ip = ctx.data.get("ip_address")
            if ip in BLOCKLIST:
                return HookResult.cancel("IP address is blocked")
            return None

        manager.register(HookPoints.PRE_LOGIN, check_ip_blocklist, priority=10)

        # Execute hooks
        context = HookContext(
            hook_point=HookPoints.PRE_LOGIN,
            subject_id="user123",
            data={"ip_address": "192.168.1.1"},
        )
        result = await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)

        if result.cancelled:
            raise AuthError(result.cancel_reason)
    """

    def __init__(self) -> None:
        """Initialize the hook manager."""
        self._hooks: dict[str, list[tuple[int, HookHandler]]] = defaultdict(list)

    def register(
        self,
        hook_point: str,
        handler: HookHandler,
        *,
        priority: int = 0,
    ) -> None:
        """Register a hook handler.

        Handlers are executed in priority order (lower numbers first).
        Multiple handlers can be registered for the same hook point.

        Args:
            hook_point: The hook point to register for.
            handler: Async function to call when hook is executed.
            priority: Execution priority (default 0, lower runs first).
        """
        self._hooks[hook_point].append((priority, handler))
        # Sort by priority after adding
        self._hooks[hook_point].sort(key=operator.itemgetter(0))

    def unregister(
        self,
        hook_point: str,
        handler: HookHandler,
    ) -> None:
        """Remove a hook handler.

        Args:
            hook_point: The hook point the handler was registered for.
            handler: The handler to remove.
        """
        if hook_point not in self._hooks:
            return

        self._hooks[hook_point] = [
            (p, h) for p, h in self._hooks[hook_point] if h != handler
        ]

    def unregister_all(self, hook_point: str) -> None:
        """Remove all handlers for a hook point.

        Args:
            hook_point: The hook point to clear handlers for.
        """
        self._hooks.pop(hook_point, None)

    def clear(self) -> None:
        """Remove all registered hooks."""
        self._hooks.clear()

    async def execute_pre_hook(
        self,
        hook_point: str,
        context: HookContext,
    ) -> HookContext:
        """Execute pre-hook handlers.

        Pre-hooks can modify the context or cancel the operation.
        Handlers are executed in priority order until one cancels
        or all have been executed.

        Args:
            hook_point: The hook point to execute.
            context: The context to pass to handlers.

        Returns:
            The (possibly modified) context after all handlers.
        """
        handlers = self._hooks.get(hook_point, [])

        for priority, handler in handlers:
            try:
                result = await handler(context)

                if result is not None:
                    # Handler returned a result
                    if not result.proceed:
                        # Operation cancelled
                        context.cancelled = True
                        context.cancel_reason = result.cancel_reason
                        logger.debug(
                            "Hook cancelled %s: %s",
                            hook_point,
                            result.cancel_reason,
                        )
                        break

                    if result.modified_data:
                        # Merge modified data
                        context.data.update(result.modified_data)

            except Exception:
                logger.exception(
                    "Error in pre-hook handler for %s (priority %d)",
                    hook_point,
                    priority,
                )
                # Continue with other handlers

        return context

    async def execute_post_hook(
        self,
        hook_point: str,
        context: HookContext,
    ) -> None:
        """Execute post-hook handlers.

        Post-hooks are for observation only and cannot modify the operation.
        All handlers are executed regardless of return value.

        Args:
            hook_point: The hook point to execute.
            context: The context to pass to handlers.
        """
        handlers = self._hooks.get(hook_point, [])

        for priority, handler in handlers:
            try:
                await handler(context)
            except Exception:
                logger.exception(
                    "Error in post-hook handler for %s (priority %d)",
                    hook_point,
                    priority,
                )
                # Continue with other handlers

    def has_hooks(self, hook_point: str) -> bool:
        """Check if any hooks are registered for a point.

        Args:
            hook_point: The hook point to check.

        Returns:
            True if at least one handler is registered.
        """
        return bool(self._hooks.get(hook_point))

    @property
    def handler_count(self) -> int:
        """Total number of registered handlers."""
        return sum(len(handlers) for handlers in self._hooks.values())

    @property
    def hook_point_count(self) -> int:
        """Number of hook points with handlers."""
        return len(self._hooks)


class HookManagerMixin:
    """Mixin for services that support hooks.

    Add this mixin to services that should execute hooks during operations.

    Example:
        class SessionService(HookManagerMixin):
            async def create_session(self, subject_id: str) -> Session:
                context = await self._run_pre_hook(
                    HookPoints.PRE_SESSION_CREATE,
                    subject_id,
                    data={"ttl": self.default_ttl},
                )

                if context.cancelled:
                    raise OperationCancelledError(context.cancel_reason)

                # Use possibly modified data
                ttl = context.data.get("ttl", self.default_ttl)
                session = await self._create_session_internal(subject_id, ttl)

                await self._run_post_hook(
                    HookPoints.POST_SESSION_CREATE,
                    subject_id,
                    results={"session_id": session.id},
                )

                return session
    """

    _hook_manager: HookManager | None = None

    def set_hook_manager(self, manager: HookManager) -> None:
        """Set the hook manager for this service.

        Args:
            manager: The hook manager to use.
        """
        self._hook_manager = manager

    @property
    def hook_manager(self) -> HookManager | None:
        """Get the hook manager, if set."""
        return self._hook_manager

    async def _run_pre_hook(
        self,
        hook_point: str,
        subject_id: str | None = None,
        *,
        data: dict[str, Any] | None = None,
    ) -> HookContext:
        """Run pre-hooks for an operation.

        If no hook manager is configured, returns an uncancelled context.

        Args:
            hook_point: The hook point to execute.
            subject_id: The subject involved in the operation.
            data: Initial context data.

        Returns:
            The context after executing all pre-hooks.
        """
        context = HookContext(
            hook_point=hook_point,
            subject_id=subject_id,
            data=data or {},
        )

        if self._hook_manager is None:
            return context

        return await self._hook_manager.execute_pre_hook(hook_point, context)

    async def _run_post_hook(
        self,
        hook_point: str,
        subject_id: str | None = None,
        *,
        data: dict[str, Any] | None = None,
        results: dict[str, Any] | None = None,
    ) -> None:
        """Run post-hooks for an operation.

        If no hook manager is configured, this is a no-op.

        Args:
            hook_point: The hook point to execute.
            subject_id: The subject involved in the operation.
            data: Context data from the operation.
            results: Results from the operation.
        """
        if self._hook_manager is None:
            return

        context = HookContext(
            hook_point=hook_point,
            subject_id=subject_id,
            data=data or {},
            results=results or {},
        )

        await self._hook_manager.execute_post_hook(hook_point, context)
