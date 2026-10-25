<%text>"""</%text>${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
<%text>"""</%text>

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB
${imports if imports else ""}
# Revision identifiers used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}

# Mirrors app.models.JSONType: JSONB on PostgreSQL, plain JSON elsewhere.
JSONType = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    <%text>"""</%text>
    Apply this revision.
    <%text>"""</%text>
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    <%text>"""</%text>
    Revert this revision.

    Every MULEGUARD migration must be reversible. If a change genuinely cannot
    be reverted, raise NotImplementedError with the reason rather than leaving
    `pass`, so an operator finds out before a rollback rather than during one.
    <%text>"""</%text>
    ${downgrades if downgrades else "pass"}
