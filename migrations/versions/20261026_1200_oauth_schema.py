"""OAuth tables under migrations; nonce and optional PKCE

Revision ID: 0_9_oauth_schema
Revises: 1_0_baseline
Create Date: 2026-10-26 12:00:00 UTC

The baseline did not import the OAuth models, so databases migrated with
it have no OAuth tables, or have tables an application created with
``create_all`` before the 0.9 changes. This revision brings both up to
date: it creates missing OAuth tables, adds
``oauth_authorization_codes.nonce`` and makes the PKCE columns nullable
(PKCE is optional for confidential clients when ``require_pkce`` is off).

On a fresh database the baseline already creates the current tables, and
this revision changes nothing.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from neozen.storage.sqlalchemy import oauth_models

# revision identifiers, used by Alembic.
revision: str = "0_9_oauth_schema"
down_revision: str | None = "1_0_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OAUTH_TABLES = [
    oauth_models.OAuthClient.__table__,
    oauth_models.OAuthGrant.__table__,
    oauth_models.OAuthAuthorizationCode.__table__,
    oauth_models.OAuthAccessToken.__table__,
    oauth_models.OAuthRefreshToken.__table__,
]


def upgrade() -> None:
    """Create missing OAuth tables, then update an older codes table."""
    bind = op.get_bind()
    oauth_models.Base.metadata.create_all(bind, tables=_OAUTH_TABLES, checkfirst=True)

    columns = {
        column["name"]: column
        for column in sa.inspect(bind).get_columns("oauth_authorization_codes")
    }
    with op.batch_alter_table("oauth_authorization_codes") as batch:
        if "nonce" not in columns:
            batch.add_column(sa.Column("nonce", sa.Text(), nullable=True))
        for name in ("code_challenge", "code_challenge_method"):
            if not columns[name]["nullable"]:
                batch.alter_column(name, existing_type=sa.String(128), nullable=True)


def downgrade() -> None:
    """Nothing to undo: the tables are part of the baseline schema now."""
