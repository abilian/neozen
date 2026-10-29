"""Rate-limit locks

Revision ID: 0_9_1_rate_limit_locks
Revises: 0_9_oauth_schema
Create Date: 2026-10-29 12:00:00 UTC

The SQL rate-limit store kept no lock: a locked-out key was free again
when its counting window ended, whatever ``lockout_duration`` said. This
revision adds the table it keeps locks in. On a fresh database the
baseline already creates it, and this revision changes nothing.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from neozen.storage.sqlalchemy import security_models

# revision identifiers, used by Alembic.
revision: str = "0_9_1_rate_limit_locks"
down_revision: str | None = "0_9_oauth_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = security_models.RateLimitLock.__table__


def upgrade() -> None:
    """Create the locks table if it is missing."""
    _TABLE.create(op.get_bind(), checkfirst=True)


def downgrade() -> None:
    """Drop the locks table."""
    _TABLE.drop(op.get_bind(), checkfirst=True)
