"""convert investigation_goals to jsonb

Revision ID: a62220985c18
Revises: 830d3a274fa7
Create Date: 2026-08-19 10:17:51.084624

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


from sqlalchemy.dialects import postgresql
revision: str = 'a62220985c18'
down_revision: Union[str, Sequence[str], None] = '830d3a274fa7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_column('investigation_cases', 'investigation_goals', schema='investigation')
    op.add_column('investigation_cases', sa.Column('investigation_goals', postgresql.JSONB(astext_type=sa.Text()), nullable=True), schema='investigation')


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('investigation_cases', 'investigation_goals', schema='investigation')
    op.add_column('investigation_cases', sa.Column('investigation_goals', postgresql.ARRAY(sa.String()), nullable=True), schema='investigation')
