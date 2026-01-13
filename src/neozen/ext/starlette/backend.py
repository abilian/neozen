"""Backend for NeoZen Starlette extension."""

from __future__ import annotations

import contextlib
import typing
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

if typing.TYPE_CHECKING:
    from starlette.responses import Response

    from neozen.core.session import SessionService
    from neozen.core.session.models import SessionModel
    from neozen.core.subject import Subject

SameSitePolicy = typing.Literal["lax", "strict", "none"]

# Type aliases
SubjectLoader = Callable[[str], Awaitable["Subject | None"]]


@dataclass
class NeoZenBackend:
    """Backend for NeoZen authentication services.

    This class holds the configuration and services needed for authentication.
    It's passed to the middleware and used by helper functions.

    Example:
        async def load_subject(subject_id: str) -> Subject | None:
            async with db.session() as session:
                repo = SubjectRepository(session=session)
                return await repo.get_one_or_none(id=subject_id)

        backend = NeoZenBackend(
            session_service=session_service,
            subject_loader=load_subject,
        )
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
            token: The session token from the cookie

        Returns:
            The session if valid, None otherwise
        """
        try:
            return await self.session_service.validate_session(token)
        except Exception:
            return None

    async def get_subject(self, subject_id: str) -> Subject | None:
        """Load a subject by ID.

        Args:
            subject_id: The subject's ID

        Returns:
            The subject if found, None otherwise
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
            subject_id: The subject's ID
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            The session token
        """
        return await self.session_service.create_session(
            subject_id=subject_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def revoke_session(self, token: str) -> None:
        """Revoke a session by its token.

        Args:
            token: The session token to revoke
        """
        with contextlib.suppress(Exception):
            await self.session_service.revoke_session_by_token(token)

    def set_session_cookie(self, response: Response, token: str) -> None:
        """Set the session cookie on a response.

        Args:
            response: The response to set the cookie on
            token: The session token
        """
        response.set_cookie(
            self.cookie_name,
            token,
            max_age=self.cookie_max_age,
            secure=self.cookie_secure,
            httponly=self.cookie_httponly,
            samesite=self.cookie_samesite,
            path=self.cookie_path,
            domain=self.cookie_domain,
        )

    def delete_session_cookie(self, response: Response) -> None:
        """Delete the session cookie from a response.

        Args:
            response: The response to delete the cookie from
        """
        response.delete_cookie(
            self.cookie_name,
            path=self.cookie_path,
            domain=self.cookie_domain,
        )


__all__ = ["NeoZenBackend", "SubjectLoader"]
