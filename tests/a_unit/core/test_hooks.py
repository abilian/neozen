# ruff: noqa: RUF029
"""Unit tests for the hook system."""

from __future__ import annotations

import pytest

from neozen.core.hooks import (
    HookContext,
    HookManager,
    HookManagerMixin,
    HookPoints,
    HookResult,
)


class TestHookContext:
    """Tests for HookContext dataclass."""

    def test_create_context(self) -> None:
        context = HookContext(
            hook_point=HookPoints.PRE_LOGIN,
            subject_id="user123",
            data={"email": "test@example.com"},
        )

        assert context.hook_point == HookPoints.PRE_LOGIN
        assert context.subject_id == "user123"
        assert context.data["email"] == "test@example.com"
        assert context.cancelled is False
        assert context.cancel_reason is None

    def test_cancel(self) -> None:
        context = HookContext(hook_point=HookPoints.PRE_LOGIN)
        context.cancel("Rate limit exceeded")

        assert context.cancelled is True
        assert context.cancel_reason == "Rate limit exceeded"

    def test_default_values(self) -> None:
        context = HookContext(hook_point=HookPoints.PRE_LOGIN)

        assert context.subject_id is None
        assert context.data == {}
        assert context.results == {}

    def test_data_is_mutable(self) -> None:
        context = HookContext(hook_point=HookPoints.PRE_LOGIN)
        context.data["key"] = "value"

        assert context.data["key"] == "value"


class TestHookResult:
    """Tests for HookResult dataclass."""

    def test_allow(self) -> None:
        result = HookResult.allow()

        assert result.proceed is True
        assert result.modified_data is None
        assert result.cancel_reason is None

    def test_cancel(self) -> None:
        result = HookResult.cancel("Operation blocked")

        assert result.proceed is False
        assert result.cancel_reason == "Operation blocked"

    def test_modify(self) -> None:
        result = HookResult.modify(foo="bar", count=42)

        assert result.proceed is True
        assert result.modified_data == {"foo": "bar", "count": 42}

    def test_default_values(self) -> None:
        result = HookResult()

        assert result.proceed is True
        assert result.modified_data is None


class TestHookPoints:
    """Tests for HookPoints constants."""

    def test_pre_hooks(self) -> None:
        assert HookPoints.PRE_LOGIN == "pre_login"
        assert HookPoints.PRE_REGISTER == "pre_register"
        assert HookPoints.PRE_PASSWORD_CHANGE == "pre_password_change"

    def test_post_hooks(self) -> None:
        assert HookPoints.POST_LOGIN == "post_login"
        assert HookPoints.POST_REGISTER == "post_register"
        assert HookPoints.POST_PASSWORD_CHANGE == "post_password_change"


@pytest.mark.anyio
class TestHookManager:
    """Tests for HookManager."""

    async def test_register_and_execute(self) -> None:
        manager = HookManager()
        executed = []

        async def handler(ctx: HookContext) -> HookResult | None:
            executed.append("handler")
            return None

        manager.register(HookPoints.PRE_LOGIN, handler)

        context = HookContext(hook_point=HookPoints.PRE_LOGIN)
        result = await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)

        assert executed == ["handler"]
        assert result.cancelled is False

    async def test_priority_ordering(self) -> None:
        manager = HookManager()
        order: list[int] = []

        async def handler_high(ctx: HookContext) -> HookResult | None:
            order.append(1)
            return None

        async def handler_low(ctx: HookContext) -> HookResult | None:
            order.append(2)
            return None

        async def handler_medium(ctx: HookContext) -> HookResult | None:
            order.append(3)
            return None

        manager.register(HookPoints.PRE_LOGIN, handler_low, priority=20)
        manager.register(HookPoints.PRE_LOGIN, handler_high, priority=10)
        manager.register(HookPoints.PRE_LOGIN, handler_medium, priority=15)

        context = HookContext(hook_point=HookPoints.PRE_LOGIN)
        await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)

        assert order == [1, 3, 2]

    async def test_pre_hook_cancellation(self) -> None:
        manager = HookManager()

        async def cancel_handler(ctx: HookContext) -> HookResult | None:
            return HookResult.cancel("Not allowed")

        async def never_runs(ctx: HookContext) -> HookResult | None:
            msg = "Should not be called"
            raise AssertionError(msg)

        manager.register(HookPoints.PRE_LOGIN, cancel_handler, priority=10)
        manager.register(HookPoints.PRE_LOGIN, never_runs, priority=20)

        context = HookContext(hook_point=HookPoints.PRE_LOGIN)
        result = await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)

        assert result.cancelled is True
        assert result.cancel_reason == "Not allowed"

    async def test_pre_hook_data_modification(self) -> None:
        manager = HookManager()

        async def modify_handler(ctx: HookContext) -> HookResult | None:
            return HookResult.modify(extra="value", count=42)

        manager.register(HookPoints.PRE_LOGIN, modify_handler)

        context = HookContext(
            hook_point=HookPoints.PRE_LOGIN,
            data={"original": "data"},
        )
        result = await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)

        assert result.data["original"] == "data"
        assert result.data["extra"] == "value"
        assert result.data["count"] == 42

    async def test_post_hook_execution(self) -> None:
        manager = HookManager()
        executed = []

        async def handler1(ctx: HookContext) -> HookResult | None:
            executed.append("handler1")
            return None

        async def handler2(ctx: HookContext) -> HookResult | None:
            executed.append("handler2")
            return None

        manager.register(HookPoints.POST_LOGIN, handler1)
        manager.register(HookPoints.POST_LOGIN, handler2)

        context = HookContext(
            hook_point=HookPoints.POST_LOGIN,
            results={"success": True},
        )
        await manager.execute_post_hook(HookPoints.POST_LOGIN, context)

        assert executed == ["handler1", "handler2"]

    async def test_handler_exception_continues(self) -> None:
        manager = HookManager()
        executed = []

        async def bad_handler(ctx: HookContext) -> HookResult | None:
            msg = "Intentional error"
            raise RuntimeError(msg)

        async def good_handler(ctx: HookContext) -> HookResult | None:
            executed.append("good")
            return None

        manager.register(HookPoints.PRE_LOGIN, bad_handler, priority=10)
        manager.register(HookPoints.PRE_LOGIN, good_handler, priority=20)

        context = HookContext(hook_point=HookPoints.PRE_LOGIN)
        await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)

        assert executed == ["good"]

    async def test_unregister(self) -> None:
        manager = HookManager()
        calls = 0

        async def handler(ctx: HookContext) -> HookResult | None:
            nonlocal calls
            calls += 1
            return None

        manager.register(HookPoints.PRE_LOGIN, handler)

        context = HookContext(hook_point=HookPoints.PRE_LOGIN)
        await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)
        assert calls == 1

        manager.unregister(HookPoints.PRE_LOGIN, handler)
        await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)
        assert calls == 1

    async def test_unregister_all(self) -> None:
        manager = HookManager()

        async def handler(ctx: HookContext) -> HookResult | None:
            return None

        manager.register(HookPoints.PRE_LOGIN, handler)
        manager.register(HookPoints.PRE_LOGIN, handler)

        assert manager.handler_count == 2

        manager.unregister_all(HookPoints.PRE_LOGIN)

        assert manager.handler_count == 0

    async def test_clear(self) -> None:
        manager = HookManager()

        async def handler(ctx: HookContext) -> HookResult | None:
            return None

        manager.register(HookPoints.PRE_LOGIN, handler)
        manager.register(HookPoints.POST_LOGIN, handler)

        assert manager.hook_point_count == 2

        manager.clear()

        assert manager.handler_count == 0
        assert manager.hook_point_count == 0

    async def test_has_hooks(self) -> None:
        manager = HookManager()

        assert manager.has_hooks(HookPoints.PRE_LOGIN) is False

        async def handler(ctx: HookContext) -> HookResult | None:
            return None

        manager.register(HookPoints.PRE_LOGIN, handler)

        assert manager.has_hooks(HookPoints.PRE_LOGIN) is True
        assert manager.has_hooks(HookPoints.POST_LOGIN) is False

    async def test_no_handlers(self) -> None:
        manager = HookManager()

        context = HookContext(hook_point=HookPoints.PRE_LOGIN)
        result = await manager.execute_pre_hook(HookPoints.PRE_LOGIN, context)

        assert result.cancelled is False


@pytest.mark.anyio
class TestHookManagerMixin:
    """Tests for HookManagerMixin."""

    async def test_run_pre_hook_with_manager(self) -> None:
        manager = HookManager()
        executed = []

        async def handler(ctx: HookContext) -> HookResult | None:
            executed.append(ctx.subject_id)
            return None

        manager.register(HookPoints.PRE_LOGIN, handler)

        class TestService(HookManagerMixin):
            async def do_login(self, subject_id: str) -> bool:
                ctx = await self._run_pre_hook(
                    HookPoints.PRE_LOGIN,
                    subject_id,
                    data={"method": "password"},
                )
                return not ctx.cancelled

        service = TestService()
        service.set_hook_manager(manager)

        result = await service.do_login("user123")

        assert result is True
        assert executed == ["user123"]

    async def test_run_pre_hook_without_manager(self) -> None:
        class TestService(HookManagerMixin):
            async def do_login(self, subject_id: str) -> bool:
                ctx = await self._run_pre_hook(HookPoints.PRE_LOGIN, subject_id)
                return not ctx.cancelled

        service = TestService()
        # No hook manager set

        result = await service.do_login("user123")

        assert result is True

    async def test_run_post_hook_with_manager(self) -> None:
        manager = HookManager()
        received_results: list[dict] = []

        async def handler(ctx: HookContext) -> HookResult | None:
            received_results.append(ctx.results.copy())
            return None

        manager.register(HookPoints.POST_LOGIN, handler)

        class TestService(HookManagerMixin):
            async def do_login(self, subject_id: str) -> None:
                await self._run_post_hook(
                    HookPoints.POST_LOGIN,
                    subject_id,
                    results={"success": True},
                )

        service = TestService()
        service.set_hook_manager(manager)

        await service.do_login("user123")

        assert received_results == [{"success": True}]

    async def test_run_post_hook_without_manager(self) -> None:
        class TestService(HookManagerMixin):
            async def do_login(self, subject_id: str) -> None:
                await self._run_post_hook(
                    HookPoints.POST_LOGIN,
                    subject_id,
                    results={"success": True},
                )

        service = TestService()
        # No hook manager set - should not raise

        await service.do_login("user123")

    async def test_hook_manager_property(self) -> None:
        manager = HookManager()

        class TestService(HookManagerMixin):
            pass

        service = TestService()
        assert service.hook_manager is None

        service.set_hook_manager(manager)
        assert service.hook_manager is manager
