"""Configuration for `neozen serve`.

Loads runtime config from (in priority order):

1. Constructor arguments (CLI flags map to these)
2. Environment variables (NEOZEN_*)
3. Built-in defaults

A NEOZEN_*_FILE variant of any string env var reads the value from
a file path — for Docker / Kubernetes secret mounts.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BIND_HOST = "0.0.0.0"  # noqa: S104 — intentional for container default
DEFAULT_BIND_PORT = 8000
DEFAULT_WORKERS = 1
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_DB_URL = "sqlite+aiosqlite:///data/neozen.db"
DEFAULT_SECRET_KEY = "change-me-in-production"


@dataclass
class ServeConfig:
    """Runtime configuration for `neozen serve`.

    Required at runtime:
        - `secret_key` (or NEOZEN_SECRET_KEY / _FILE)
        - `db_url`     (or NEOZEN_DATABASE_URL / _FILE)

    Optional:
        - `bind_host` (default 0.0.0.0)
        - `bind_port` (default 8000)
        - `workers`   (default 1)
        - `log_level` (default INFO)
        - `bootstrap_admin` (default True)
        - `bootstrap_admin_email` (default admin@localhost)
        - `cookie_secure` (default True): set the Secure flag on the admin
          session cookie. Turn it off only to serve over plain HTTP.
    """

    db_url: str = DEFAULT_DB_URL
    secret_key: str = DEFAULT_SECRET_KEY
    bind_host: str = DEFAULT_BIND_HOST
    bind_port: int = DEFAULT_BIND_PORT
    workers: int = DEFAULT_WORKERS
    log_level: str = DEFAULT_LOG_LEVEL

    bootstrap_admin: bool = True
    bootstrap_admin_email: str = "admin@localhost"
    cookie_secure: bool = True

    # Populated by validate(); empty list means OK.
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServeConfig:
        """Build a ServeConfig from environment variables.

        Honours `NEOZEN_*_FILE` for any string field, so Docker secret
        mounts work without extra glue.
        """
        e = env if env is not None else os.environ

        return cls(
            db_url=_str_env(e, "NEOZEN_DATABASE_URL", DEFAULT_DB_URL),
            secret_key=_str_env(e, "NEOZEN_SECRET_KEY", DEFAULT_SECRET_KEY),
            bind_host=_str_env(e, "NEOZEN_BIND_HOST", DEFAULT_BIND_HOST),
            bind_port=int(_str_env(e, "NEOZEN_BIND_PORT", str(DEFAULT_BIND_PORT))),
            workers=int(_str_env(e, "NEOZEN_WORKERS", str(DEFAULT_WORKERS))),
            log_level=_str_env(e, "NEOZEN_LOG_LEVEL", DEFAULT_LOG_LEVEL),
            bootstrap_admin=_bool_env(e, "NEOZEN_BOOTSTRAP_ADMIN", default=True),
            bootstrap_admin_email=_str_env(
                e, "NEOZEN_BOOTSTRAP_ADMIN_EMAIL", "admin@localhost"
            ),
            cookie_secure=_bool_env(e, "NEOZEN_COOKIE_SECURE", default=True),
        )

    def validate(self) -> list[str]:
        """Return a list of warning messages. Empty list means OK.

        Warnings are surfaced at startup but do not prevent the server
        from booting — production hardening is the operator's call.
        """
        warnings: list[str] = []
        if self.secret_key == DEFAULT_SECRET_KEY:
            warnings.append(
                "NEOZEN_SECRET_KEY is unset; using the insecure built-in "
                "default. Set NEOZEN_SECRET_KEY (or NEOZEN_SECRET_KEY_FILE) "
                "before exposing this to anything but localhost."
            )
        if self.bind_host == "0.0.0.0":  # noqa: S104
            # This is the right container default, so it's only a soft note.
            pass
        if self.bind_port < 1 or self.bind_port > 65535:
            warnings.append(
                f"NEOZEN_BIND_PORT={self.bind_port} is outside the valid "
                "TCP port range; the server will not bind."
            )
        if self.workers < 1:
            warnings.append(
                f"NEOZEN_WORKERS={self.workers} is less than 1; defaulting to 1 worker."
            )
        self.warnings = warnings
        return warnings


def _str_env(env: Mapping[str, str], name: str, default: str) -> str:
    """Read an env var, falling back to `<NAME>_FILE` then to default."""
    if env.get(name):
        return env[name]
    file_var = f"{name}_FILE"
    if env.get(file_var):
        path = Path(env[file_var])
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    return default


def _bool_env(env: Mapping[str, str], name: str, *, default: bool) -> bool:
    if name not in env:
        return default
    raw = env[name].strip().lower()
    if raw in {"1", "true", "yes", "on", "t", "y"}:
        return True
    if raw in {"0", "false", "no", "off", "f", "n"}:
        return False
    return default
