"""Litestar rate-limit middleware, set up as its docstring says."""

from __future__ import annotations

from datetime import timedelta

from litestar import Litestar, get
from litestar.datastructures import State
from litestar.testing import TestClient

from neozen.core.security import InMemoryRateLimitStore, RateLimitConfig, RateLimiter
from neozen.ext.litestar.rate_limit import RateLimitMiddleware


@get("/", sync_to_thread=False)
def index() -> str:
    return "ok"


def test_limiter_from_app_state_limits_requests() -> None:
    limiter = RateLimiter(
        RateLimitConfig(max_attempts=2, window=timedelta(minutes=1)),
        InMemoryRateLimitStore(),
    )
    app = Litestar(
        route_handlers=[index],
        middleware=[RateLimitMiddleware],
        state=State({"rate_limiter": limiter}),
    )
    with TestClient(app) as client:
        statuses = [client.get("/").status_code for _ in range(3)]
    assert statuses == [200, 200, 429]


def test_missing_limiter_is_an_error_not_a_free_pass() -> None:
    app = Litestar(route_handlers=[index], middleware=[RateLimitMiddleware])
    with TestClient(app) as client:
        assert client.get("/").status_code == 500
