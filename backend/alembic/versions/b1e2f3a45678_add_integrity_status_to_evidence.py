"""Add integrity_status column to evidence

Revision ID: b1e2f3a45678
Revises: 244bb91259cf
Create Date: 2026-08-18 22:27:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b1e2f3a45678'
down_revision: Union[str, Sequence[str], None] = '244bb91259cf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE acquisition.evidence 
        ADD COLUMN IF NOT EXISTS integrity_status TEXT NOT NULL DEFAULT 'pending';
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE acquisition.evidence 
        DROP COLUMN IF EXISTS integrity_status;
    """)
