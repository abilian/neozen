"""NeoZen Hook System.

The hook system allows intercepting and modifying authentication flows.

Hooks come in two types:

1. **Pre-hooks** - Run before an operation
   - Can modify the context data
   - Can cancel the operation
   - Useful for validation, rate limiting, access control

2. **Post-hooks** - Run after an operation
   - Observe only (cannot modify)
   - Useful for logging, notifications, cleanup

Example:
    from neozen.core.hooks import HookManager, HookPoints, HookContext, HookResult

    manager = HookManager()

    # Pre-hook that can cancel login
    async def check_ip_blocklist(ctx: HookContext) -> HookResult | None:
        ip = ctx.data.get("ip_address")
        if ip in BLOCKED_IPS:
            return HookResult.cancel("IP address is blocked")
        return None

    # Pre-hook that modifies data
    async def add_metadata(ctx: HookContext) -> HookResult | None:
        return HookResult.modify(login_time=datetime.now())

    # Post-hook for logging
    async def log_login(ctx: HookContext) -> None:
        if ctx.results.get("success"):
            logger.info(f"User {ctx.subject_id} logged in")

    manager.register(HookPoints.PRE_LOGIN, check_ip_blocklist, priority=10)
    manager.register(HookPoints.PRE_LOGIN, add_metadata, priority=20)
    manager.register(HookPoints.POST_LOGIN, log_login)

For services that use hooks, use the HookManagerMixin:

    from neozen.core.hooks import HookManagerMixin, HookPoints

    class MyAuthService(HookManagerMixin):
        async def login(self, email: str, password: str) -> User:
            ctx = await self._run_pre_hook(
                HookPoints.PRE_LOGIN,
                data={"email": email},
            )

            if ctx.cancelled:
                raise LoginCancelledError(ctx.cancel_reason)

            # Perform login...
            user = await self._authenticate(email, password)

            await self._run_post_hook(
                HookPoints.POST_LOGIN,
                subject_id=user.id,
                results={"success": True},
            )

            return user

    service = MyAuthService()
    service.set_hook_manager(manager)
"""

from __future__ import annotations

from .manager import HookHandler, HookManager, HookManagerMixin
from .types import HookContext, HookPoints, HookResult

__all__ = [
    # Types
    "HookContext",
    "HookPoints",
    "HookResult",
    # Manager
    "HookManager",
    "HookHandler",
    "HookManagerMixin",
]
