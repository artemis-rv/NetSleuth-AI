"""v1.3 assessment tables and mitre/attack_chain column additions

Revision ID: c4d7e8f90123
Revises: b1e2f3a45678
Create Date: 2026-08-19 06:40:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB, ARRAY


# revision identifiers, used by Alembic.
revision = 'c4d7e8f90123'
down_revision = 'b1e2f3a45678'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ─────────────────────────────────────────────
    # AttackChain: add status column (M3-008)
    # ─────────────────────────────────────────────
    op.add_column('attack_chains',
        sa.Column('status', sa.String(), nullable=False, server_default='none'),
        schema='investigation'
    )

    # ─────────────────────────────────────────────
    # MitreMapping: add V1.3 contract columns (M3-002a, M3-009, M3-010, M3-011)
    # ─────────────────────────────────────────────
    op.add_column('mitre_mappings',
        sa.Column('tactic_id', sa.String(), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('mapping_status', sa.String(), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('behavior_id', UUID(as_uuid=True), nullable=True),
        schema='investigation'
    )
    op.create_foreign_key(
        'fk_mitre_mappings__behavior',
        'mitre_mappings', 'behaviors',
        ['behavior_id'], ['behavior_id'],
        source_schema='investigation', referent_schema='investigation',
        ondelete='RESTRICT'
    )
    op.add_column('mitre_mappings',
        sa.Column('evidence_ids', ARRAY(sa.String()), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('source_finding_ids', ARRAY(sa.String()), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('detection_strategy_ids', ARRAY(sa.String()), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('analytic_ids', ARRAY(sa.String()), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('data_component_ids', ARRAY(sa.String()), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('channels', ARRAY(sa.String()), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('first_seen', TIMESTAMP(timezone=True), nullable=True),
        schema='investigation'
    )
    op.add_column('mitre_mappings',
        sa.Column('last_seen', TIMESTAMP(timezone=True), nullable=True),
        schema='investigation'
    )

    # ─────────────────────────────────────────────
    # V1.3 Assessment Tables (M3-001a/b/c/d)
    # ─────────────────────────────────────────────

    # investigation.hypotheses
    op.create_table(
        'hypotheses',
        sa.Column('hypothesis_id', UUID(as_uuid=True), primary_key=True),
        sa.Column('case_id', UUID(as_uuid=True), sa.ForeignKey('investigation.investigation_cases.case_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('statement', sa.String(), nullable=False),
        sa.Column('hypothesis_type', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, server_default='POTENTIAL'),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('supporting_evidence_ids', ARRAY(sa.String()), nullable=False),
        sa.Column('supporting_finding_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('related_entity_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('related_mitre_mapping_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('first_seen', TIMESTAMP(timezone=True), nullable=True),
        sa.Column('last_seen', TIMESTAMP(timezone=True), nullable=True),
        sa.Column('supporting_reasons', ARRAY(sa.String()), nullable=True),
        sa.Column('missing_evidence', ARRAY(sa.String()), nullable=True),
        sa.Column('created_at', TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('now()')),
        schema='investigation'
    )
    op.create_index('ix_hypotheses__case', 'hypotheses', ['case_id'], schema='investigation')

    # investigation.hypothesis_validations
    op.create_table(
        'hypothesis_validations',
        sa.Column('validation_id', UUID(as_uuid=True), primary_key=True),
        sa.Column('case_id', UUID(as_uuid=True), sa.ForeignKey('investigation.investigation_cases.case_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('hypothesis_id', UUID(as_uuid=True), sa.ForeignKey('investigation.hypotheses.hypothesis_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('validation_status', sa.String(), nullable=False),
        sa.Column('supporting_evidence_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('contradicting_evidence_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('supporting_reasons', ARRAY(sa.String()), nullable=True),
        sa.Column('contradicting_reasons', ARRAY(sa.String()), nullable=True),
        sa.Column('missing_evidence', ARRAY(sa.String()), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('validated_at', TIMESTAMP(timezone=True), nullable=False),
        sa.Column('created_at', TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('now()')),
        schema='investigation'
    )
    op.create_index('ix_hyp_validations__case', 'hypothesis_validations', ['case_id'], schema='investigation')
    op.create_index('ix_hyp_validations__hyp', 'hypothesis_validations', ['hypothesis_id'], schema='investigation')

    # investigation.root_causes
    op.create_table(
        'root_causes',
        sa.Column('root_cause_id', UUID(as_uuid=True), primary_key=True),
        sa.Column('case_id', UUID(as_uuid=True), sa.ForeignKey('investigation.investigation_cases.case_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('statement', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, server_default='POTENTIAL'),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('supporting_hypothesis_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('supporting_evidence_ids', ARRAY(sa.String()), nullable=False),
        sa.Column('supporting_finding_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('rationale', ARRAY(sa.String()), nullable=True),
        sa.Column('missing_evidence', ARRAY(sa.String()), nullable=True),
        sa.Column('created_at', TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('now()')),
        schema='investigation'
    )
    op.create_index('ix_root_causes__case', 'root_causes', ['case_id'], schema='investigation')

    # investigation.impact_assessments
    op.create_table(
        'impact_assessments',
        sa.Column('impact_id', UUID(as_uuid=True), primary_key=True),
        sa.Column('case_id', UUID(as_uuid=True), sa.ForeignKey('investigation.investigation_cases.case_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('statement', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, server_default='POTENTIAL'),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('supporting_evidence_ids', ARRAY(sa.String()), nullable=False),
        sa.Column('supporting_finding_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('affected_entity_ids', ARRAY(sa.String()), nullable=True),
        sa.Column('rationale', ARRAY(sa.String()), nullable=True),
        sa.Column('missing_evidence', ARRAY(sa.String()), nullable=True),
        sa.Column('created_at', TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('now()')),
        schema='investigation'
    )
    op.create_index('ix_impact_assessments__case', 'impact_assessments', ['case_id'], schema='investigation')


def downgrade() -> None:
    # Drop V1.3 assessment tables
    op.drop_table('impact_assessments', schema='investigation')
    op.drop_table('root_causes', schema='investigation')
    op.drop_table('hypothesis_validations', schema='investigation')
    op.drop_table('hypotheses', schema='investigation')

    # Drop MITRE new columns
    op.drop_constraint('fk_mitre_mappings__behavior', 'mitre_mappings', schema='investigation', type_='foreignkey')
    for col in ['last_seen', 'first_seen', 'channels', 'data_component_ids', 'analytic_ids',
                'detection_strategy_ids', 'source_finding_ids', 'evidence_ids',
                'behavior_id', 'mapping_status', 'tactic_id']:
        op.drop_column('mitre_mappings', col, schema='investigation')

    # Drop attack chain status
    op.drop_column('attack_chains', 'status', schema='investigation')
