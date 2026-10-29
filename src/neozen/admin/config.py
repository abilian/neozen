"""Admin UI configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AdminConfig:
    """Configuration for the NeoZen Admin UI.

    Attributes:
        db_url: SQLAlchemy database URL
        secret_key: Secret key for session encryption
        require_role: Role required to access admin (default: "admin")
        cookie_name: Session cookie name
        cookie_secure: Whether to set Secure flag on cookies
        session_dir: Where sign-in sessions are kept. None keeps them in
            memory, which suits one process; give a directory when several
            workers serve the console, or to keep sessions across restarts.
    """

    db_url: str
    secret_key: str
    require_role: str = "admin"
    cookie_name: str = "neozen_admin_session"
    cookie_secure: bool = False
    session_dir: Path | None = None
    templates_dir: Path = field(
        default_factory=lambda: Path(__file__).parent / "templates"
    )


__all__ = ["AdminConfig"]
