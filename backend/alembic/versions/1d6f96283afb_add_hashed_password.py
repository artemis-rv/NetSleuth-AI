"""Add hashed_password

Revision ID: 1d6f96283afb
Revises: ac8190b4c26a
Create Date: 2026-08-17 23:59:57.161668

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '1d6f96283afb'
down_revision: Union[str, Sequence[str], None] = 'ac8190b4c26a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('users', sa.Column('hashed_password', sa.String(), nullable=True), schema='identity')


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'hashed_password', schema='identity')
