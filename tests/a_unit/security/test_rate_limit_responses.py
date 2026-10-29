"""The 429 response every adapter sends."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from neozen.core.security import RateLimitResult
from neozen.web.rate_limit import DEFAULT_RETRY_AFTER, too_many_requests


def test_denial_carries_retry_after_and_limit_headers() -> None:
    reset = datetime(2026, 10, 29, tzinfo=UTC)
    result = RateLimitResult(
        allowed=False,
        remaining_attempts=0,
        reset_at=reset,
        retry_after=timedelta(seconds=90),
    )

    body, headers = too_many_requests(result, 5)

    assert body["retry_after"] == 90
    assert headers == {
        "Retry-After": "90",
        "X-RateLimit-Limit": "5",
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": str(int(reset.timestamp())),
    }


def test_denial_without_retry_after_uses_the_default() -> None:
    result = RateLimitResult(allowed=False, remaining_attempts=0)
    assert too_many_requests(result, 5)[1]["Retry-After"] == str(DEFAULT_RETRY_AFTER)
