"""Rate limit responses, for every framework adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from neozen.core.security import RateLimitResult

# When a denial carries no retry_after.
DEFAULT_RETRY_AFTER = 60

LIMIT_EXCEEDED = "Rate limit exceeded. Please try again later."


def retry_after_seconds(result: RateLimitResult) -> int:
    """Seconds before the client may try again."""
    if result.retry_after is None:
        return DEFAULT_RETRY_AFTER
    return int(result.retry_after.total_seconds())


def rate_limit_headers(result: RateLimitResult, limit: int) -> dict[str, str]:
    """``X-RateLimit-*`` headers for a response, allowed or not."""
    headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(result.remaining_attempts),
    }
    if result.reset_at:
        headers["X-RateLimit-Reset"] = str(int(result.reset_at.timestamp()))
    return headers


def too_many_requests(
    result: RateLimitResult, limit: int, message: str = LIMIT_EXCEEDED
) -> tuple[dict[str, object], dict[str, str]]:
    """Body and headers of the 429 response for a denied request."""
    retry_after = retry_after_seconds(result)
    body: dict[str, object] = {
        "error": "Too Many Requests",
        "message": message,
        "retry_after": retry_after,
    }
    headers = {"Retry-After": str(retry_after), **rate_limit_headers(result, limit)}
    return body, headers


__all__ = [
    "DEFAULT_RETRY_AFTER",
    "LIMIT_EXCEEDED",
    "rate_limit_headers",
    "retry_after_seconds",
    "too_many_requests",
]
