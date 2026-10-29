"""The 401 and 403 bodies every framework adapter sends to API clients."""

from __future__ import annotations


def unauthorized_body() -> dict[str, str]:
    """No signed-in user (401)."""
    return {"error": "unauthorized", "detail": "Authentication required"}


def forbidden_body(detail: str = "Permission denied") -> dict[str, str]:
    """A signed-in user without the role or permission (403)."""
    return {"error": "forbidden", "detail": detail}


__all__ = ["forbidden_body", "unauthorized_body"]
