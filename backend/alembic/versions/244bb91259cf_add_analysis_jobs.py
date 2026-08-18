"""add_analysis_jobs

Revision ID: 244bb91259cf
Revises: 1d6f96283afb
Create Date: 2026-08-18 01:02:24.518856

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '244bb91259cf'
down_revision: Union[str, None] = '1d6f96283afb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'analysis_jobs',
        sa.Column('analysis_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('investigation.investigation_cases.case_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('acquisition_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('acquisition.acquisitions.acquisition_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('current_stage', sa.String(), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=True),
        sa.Column('error_code', sa.String(), nullable=True),
        sa.Column('error_message', sa.String(), nullable=True),
        sa.Column('started_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('completed_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        schema='investigation'
    )


def downgrade() -> None:
    op.drop_table('analysis_jobs', schema='investigation')
