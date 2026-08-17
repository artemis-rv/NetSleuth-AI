"""Add relationship timestamps

Revision ID: ac8190b4c26a
Revises: 8ffde38e6da6
Create Date: 2026-08-17 21:13:50.544924

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ac8190b4c26a'
down_revision: Union[str, Sequence[str], None] = '8ffde38e6da6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute('''
        ALTER TABLE investigation.relationships 
        ADD COLUMN first_seen TIMESTAMPTZ,
        ADD COLUMN last_seen TIMESTAMPTZ;

        ALTER TABLE investigation.relationships
        ADD CONSTRAINT ck_rel__time CHECK (last_seen >= first_seen);
    ''')


def downgrade() -> None:
    op.execute('''
        ALTER TABLE investigation.relationships DROP CONSTRAINT ck_rel__time;
        ALTER TABLE investigation.relationships DROP COLUMN last_seen;
        ALTER TABLE investigation.relationships DROP COLUMN first_seen;
    ''')
