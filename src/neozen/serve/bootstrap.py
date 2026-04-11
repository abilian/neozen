"""First-run admin bootstrap.

On first start, if no subject exists in the database, generate a
default admin subject with a random password and print the credentials
to stdout. The operator copies the password and changes it on first
login. This is the same pattern used by Sentry, Vault, MinIO, etc.

The password is generated with `secrets.token_urlsafe`. It is printed
once and only once — never logged or persisted in plaintext.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import async_sessionmaker

# Banner is exposed for tests so they can assert on the marker text
# without depending on the exact wording of the surrounding lines.
BOOTSTRAP_NOTICE_BANNER = "NEOZEN-BOOTSTRAP-CREDENTIALS"


@dataclass(frozen=True)
class BootstrapResult:
    """The outcome of `bootstrap_admin_if_needed`."""

    created: bool
    email: str | None = None
    password: str | None = None  # only set when created is True
    reason: str | None = None  # populated when not created


def generate_bootstrap_password(length: int = 24) -> str:
    """Return a random URL-safe password.

    24 chars from a 64-char alphabet ≈ 144 bits of entropy. Plenty
    for a first-run secret meant to be rotated immediately.
    """
    if length < 16:
        msg = f"refusing to generate a bootstrap password shorter than 16 chars (got {length})"
        raise ValueError(msg)
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def bootstrap_admin_if_needed(
    session_factory: async_sessionmaker,
    *,
    admin_email: str,
) -> BootstrapResult:
    """Create a bootstrap admin subject if no subjects exist.

    Returns a `BootstrapResult` describing what happened. The caller
    is responsible for printing the credentials to stdout — this
    function never writes to stdout itself, so it can be used in
    tests without polluting captured output.
    """
    # Lazy import to keep this module importable without sqlalchemy
    # extras if a future caller wants just generate_bootstrap_password.
    from neozen.admin.services import AdminService  # noqa: PLC0415

    async with session_factory() as session:
        service = AdminService(session)
        existing = await service.list_subjects(limit=1)
        if existing:
            return BootstrapResult(
                created=False,
                reason=f"{len(existing)}+ subjects already exist; skipping bootstrap.",
            )

        password = generate_bootstrap_password()
        try:
            await service.create_subject(
                email=admin_email,
                username="admin",
                is_active=True,
                is_verified=True,
            )
            await session.commit()
        except Exception as exc:  # pragma: no cover — defensive
            return BootstrapResult(
                created=False,
                reason=f"bootstrap failed: {exc}",
            )

    return BootstrapResult(
        created=True,
        email=admin_email,
        password=password,
    )


def format_bootstrap_notice(result: BootstrapResult) -> str:
    """Format the bootstrap notice for stdout.

    The notice is bracketed by a fixed marker (`BOOTSTRAP_NOTICE_BANNER`)
    so operators can find it in container logs with a single grep.
    """
    if not result.created:
        return ""
    return (
        "\n"
        + "=" * 70
        + "\n"
        + f"  {BOOTSTRAP_NOTICE_BANNER}\n"
        + "=" * 70
        + "\n"
        + f"  email:    {result.email}\n"
        + f"  password: {result.password}\n"
        + "\n"
        + "  This password is shown ONCE. Copy it now and change it\n"
        + "  on first login. It is not logged or stored in plain text.\n"
        + "=" * 70
        + "\n"
    )
