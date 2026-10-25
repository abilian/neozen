"""Shared authentication backend base class.

Provides common session management functionality used by framework-specific backends.
"""

from __future__ import annotations

import contextlib
import typing
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from neozen.core.session import SessionError

if typing.TYPE_CHECKING:
    from neozen.core.session import SessionService
    from neozen.core.session.models import SessionModel
    from neozen.core.subject import Subject

SameSitePolicy = typing.Literal["lax", "strict", "none"]
SubjectLoader = Callable[[str], Awaitable["Subject | None"]]


@dataclass
class AuthBackendBase:
    """Base class for authentication backends.

    Provides common session management and cookie handling functionality.
    Framework-specific backends inherit from this class.

    Attributes:
        session_service: Service for session management.
        subject_loader: Async function to load subjects by ID.
        cookie_name: Name of the session cookie.
        cookie_max_age: Cookie max age in seconds.
        cookie_secure: Whether cookie requires HTTPS.
        cookie_httponly: Whether cookie is HTTP-only.
        cookie_samesite: SameSite cookie policy.
        cookie_path: Cookie path.
        cookie_domain: Cookie domain (None for current domain).
    """

    session_service: SessionService[typing.Any]
    subject_loader: SubjectLoader

    # Cookie configuration
    cookie_name: str = "neozen_session"
    cookie_max_age: int = 86400 * 7  # 7 days
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: SameSitePolicy = "lax"
    cookie_path: str = "/"
    cookie_domain: str | None = None

    async def get_session(self, token: str) -> SessionModel | None:
        """Validate a session token and return the session.

        Args:
            token: The session token from the cookie.

        Returns:
            The session if valid, None otherwise.
        """
        try:
            return await self.session_service.validate_session(token)
        except SessionError:
            return None

    async def get_subject(self, subject_id: str) -> Subject | None:
        """Load a subject by ID.

        Args:
            subject_id: The subject's ID.

        Returns:
            The subject if found, None otherwise.
        """
        return await self.subject_loader(subject_id)

    async def create_session(
        self,
        subject_id: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        """Create a new session for a subject.

        Args:
            subject_id: The subject's ID.
            ip_address: Client IP address.
            user_agent: Client user agent.

        Returns:
            The session token.
        """
        return await self.session_service.create_session(
            subject_id=subject_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def revoke_session(self, token: str) -> None:
        """Revoke a session by its token.

        Args:
            token: The session token to revoke.
        """
        with contextlib.suppress(SessionError):
            await self.session_service.revoke_session_by_token(token)

    def _get_cookie_kwargs(self) -> dict[str, typing.Any]:
        """Get common cookie kwargs for set_cookie calls.

        Returns:
            Dictionary of cookie parameters.
        """
        return {
            "max_age": self.cookie_max_age,
            "secure": self.cookie_secure,
            "httponly": self.cookie_httponly,
            "samesite": self.cookie_samesite,
            "path": self.cookie_path,
            "domain": self.cookie_domain,
        }


__all__ = ["AuthBackendBase", "SameSitePolicy", "SubjectLoader"]
