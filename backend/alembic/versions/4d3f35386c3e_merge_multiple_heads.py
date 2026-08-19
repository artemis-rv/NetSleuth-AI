"""Merge multiple heads

Revision ID: 4d3f35386c3e
Revises: 830d3a274fa7, c4d7e8f90123
Create Date: 2026-08-19 08:27:57.816501

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4d3f35386c3e'
down_revision: Union[str, Sequence[str], None] = ('830d3a274fa7', 'c4d7e8f90123')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
