"""make_service_nullable

Revision ID: 830d3a274fa7
Revises: b1e2f3a45678
Create Date: 2026-08-18 23:17:52.389129

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '830d3a274fa7'
down_revision: Union[str, Sequence[str], None] = 'b1e2f3a45678'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute('''
        ALTER TABLE intelligence.flows 
        ALTER COLUMN service DROP NOT NULL;
    ''')


def downgrade() -> None:
    """Downgrade schema."""
    op.execute('''
        ALTER TABLE intelligence.flows 
        ALTER COLUMN service SET NOT NULL;
    ''')
