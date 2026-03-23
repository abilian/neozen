"""Backend for NeoZen Starlette extension."""

from __future__ import annotations

import typing
from dataclasses import dataclass

from neozen.web.auth import AuthBackendBase, SameSitePolicy, SubjectLoader

if typing.TYPE_CHECKING:
    from starlette.responses import Response


@dataclass
class NeoZenBackend(AuthBackendBase):
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

    def set_session_cookie(self, response: Response, token: str) -> None:
        """Set the session cookie on a response.

        Args:
            response: The response to set the cookie on.
            token: The session token.
        """
        response.set_cookie(
            self.cookie_name,
            token,
            **self._get_cookie_kwargs(),
        )

    def delete_session_cookie(self, response: Response) -> None:
        """Delete the session cookie from a response.

        Args:
            response: The response to delete the cookie from.
        """
        response.delete_cookie(
            self.cookie_name,
            path=self.cookie_path,
            domain=self.cookie_domain,
        )


__all__ = ["NeoZenBackend", "SameSitePolicy", "SubjectLoader"]
