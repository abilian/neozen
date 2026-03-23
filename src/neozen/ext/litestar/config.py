"""Configuration for NeoZen Litestar extension."""

from __future__ import annotations

import typing
from dataclasses import dataclass, field

from neozen.web.auth import AuthBackendBase, SameSitePolicy, SubjectLoader

if typing.TYPE_CHECKING:
    from litestar import Response


@dataclass
class NeoZenConfig(AuthBackendBase):
    """Configuration for NeoZen Litestar integration.

    This configuration is passed to NeoZenPlugin to set up authentication.

    Example:
        async def load_subject(subject_id: str) -> Subject | None:
            return await user_repo.get(subject_id)

        config = NeoZenConfig(
            session_service=session_service,
            subject_loader=load_subject,
            login_path="/login",
        )

        app = Litestar(
            plugins=[NeoZenPlugin(config)],
        )
    """

    # Authentication paths
    login_path: str | None = "/login"
    exclude_paths: list[str] = field(default_factory=list)

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


__all__ = ["NeoZenConfig", "SameSitePolicy", "SubjectLoader"]
