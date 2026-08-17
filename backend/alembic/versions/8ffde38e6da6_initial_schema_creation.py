"""Initial schema creation

Revision ID: 8ffde38e6da6
Revises: 
Create Date: 2026-08-17 19:05:31.341189

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8ffde38e6da6'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute('''
-- 1. SCHEMAS
CREATE SCHEMA identity;
CREATE SCHEMA acquisition;
CREATE SCHEMA intelligence;
CREATE SCHEMA analytics;
CREATE SCHEMA investigation;
CREATE SCHEMA custody;
CREATE SCHEMA audit;

-- 2. ACQUISITION SCHEMA
CREATE TABLE acquisition.acquisitions (
    acquisition_id UUID PRIMARY KEY,
    file_name TEXT NOT NULL,
    file_size BIGINT,
    sha256 CHAR(64) NOT NULL,
    format TEXT NOT NULL,
    source_type TEXT NOT NULL,
    capture_interface TEXT,
    capture_filter TEXT,
    source_environment TEXT,
    capture_started_at TIMESTAMPTZ,
    capture_ended_at TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL,
    CONSTRAINT uq_acquisitions__sha256 UNIQUE (sha256),
    CONSTRAINT ck_acquisitions__sha256 CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_acquisitions__status CHECK (status IN ('ingesting', 'complete', 'failed', 'archived'))
);

CREATE TABLE acquisition.evidence (
    evidence_id UUID PRIMARY KEY,
    acquisition_id UUID NOT NULL,
    minio_bucket TEXT NOT NULL,
    object_key TEXT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    size_bytes BIGINT,
    content_type TEXT,
    packet_refs JSONB,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_evidence__object_key UNIQUE (object_key),
    CONSTRAINT fk_evidence__acquisitions FOREIGN KEY (acquisition_id) REFERENCES acquisition.acquisitions(acquisition_id) ON DELETE RESTRICT
);

-- 3. INTELLIGENCE SCHEMA
CREATE TABLE intelligence.flows (
    flow_id UUID PRIMARY KEY,
    zeek_uid TEXT NOT NULL,
    acquisition_id UUID NOT NULL,
    evidence_id UUID,
    timestamp TIMESTAMPTZ NOT NULL,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    src_ip INET NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip INET NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT NOT NULL,
    duration FLOAT,
    orig_bytes BIGINT,
    resp_bytes BIGINT,
    orig_packets INTEGER,
    resp_packets INTEGER,
    connection_state TEXT,
    pcap_frame_start BIGINT,
    pcap_frame_end BIGINT,
    pcap_byte_offset BIGINT,
    pcap_timestamp_start TIMESTAMPTZ,
    pcap_timestamp_end TIMESTAMPTZ,
    provenance JSONB,
    CONSTRAINT uq_flows__zeek_uid_acq UNIQUE (zeek_uid, acquisition_id),
    CONSTRAINT fk_flows__acquisitions FOREIGN KEY (acquisition_id) REFERENCES acquisition.acquisitions(acquisition_id) ON DELETE RESTRICT,
    CONSTRAINT fk_flows__evidence FOREIGN KEY (evidence_id) REFERENCES acquisition.evidence(evidence_id) ON DELETE RESTRICT,
    CONSTRAINT ck_flows__src_port CHECK (src_port >= 0 AND src_port <= 65535),
    CONSTRAINT ck_flows__dst_port CHECK (dst_port >= 0 AND dst_port <= 65535),
    CONSTRAINT ck_flows__duration CHECK (duration >= 0),
    CONSTRAINT ck_flows__orig_bytes CHECK (orig_bytes >= 0),
    CONSTRAINT ck_flows__resp_bytes CHECK (resp_bytes >= 0),
    CONSTRAINT ck_flows__orig_pkts CHECK (orig_packets >= 0),
    CONSTRAINT ck_flows__resp_pkts CHECK (resp_packets >= 0)
);

CREATE TABLE intelligence.protocol_events (
    event_id UUID PRIMARY KEY,
    flow_id UUID NOT NULL,
    zeek_uid TEXT NOT NULL,
    acquisition_id UUID NOT NULL,
    evidence_id UUID,
    protocol TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    protocol_data JSONB NOT NULL,
    provenance JSONB,
    CONSTRAINT fk_protocol_events__flows FOREIGN KEY (flow_id) REFERENCES intelligence.flows(flow_id) ON DELETE RESTRICT,
    CONSTRAINT fk_protocol_events__acquisitions FOREIGN KEY (acquisition_id) REFERENCES acquisition.acquisitions(acquisition_id) ON DELETE RESTRICT,
    CONSTRAINT fk_protocol_events__evidence FOREIGN KEY (evidence_id) REFERENCES acquisition.evidence(evidence_id) ON DELETE RESTRICT
);

CREATE TABLE intelligence.artifacts (
    artifact_id UUID PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_event_id UUID,
    flow_id UUID,
    acquisition_id UUID NOT NULL,
    evidence_id UUID,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    provenance JSONB,
    CONSTRAINT fk_artifacts__protocol_events FOREIGN KEY (source_event_id) REFERENCES intelligence.protocol_events(event_id) ON DELETE RESTRICT,
    CONSTRAINT fk_artifacts__flows FOREIGN KEY (flow_id) REFERENCES intelligence.flows(flow_id) ON DELETE RESTRICT,
    CONSTRAINT fk_artifacts__acquisitions FOREIGN KEY (acquisition_id) REFERENCES acquisition.acquisitions(acquisition_id) ON DELETE RESTRICT,
    CONSTRAINT fk_artifacts__evidence FOREIGN KEY (evidence_id) REFERENCES acquisition.evidence(evidence_id) ON DELETE RESTRICT
);

-- 4. ANALYTICS SCHEMA
CREATE TABLE analytics.model_registry (
    model_id UUID PRIMARY KEY,
    model_name TEXT NOT NULL,
    model_type TEXT NOT NULL,
    version TEXT NOT NULL,
    feature_schema_version TEXT,
    training_dataset_version TEXT,
    artifact_object_key TEXT,
    artifact_sha256 TEXT,
    metrics JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE analytics.findings_packages (
    package_id UUID PRIMARY KEY,
    acquisition_id UUID NOT NULL,
    source_package_id TEXT NOT NULL,
    analysis_engine_version TEXT NOT NULL,
    feature_schema_version TEXT,
    anomaly_model_version TEXT,
    classifier_model_version TEXT,
    findings_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_findings_packages__acquisitions FOREIGN KEY (acquisition_id) REFERENCES acquisition.acquisitions(acquisition_id) ON DELETE RESTRICT
);

CREATE TABLE analytics.findings (
    finding_id UUID PRIMARY KEY,
    package_id UUID NOT NULL,
    acquisition_id UUID NOT NULL,
    activity TEXT NOT NULL,
    decision_state TEXT NOT NULL,
    risk_score FLOAT,
    confidence FLOAT,
    anomaly_score FLOAT,
    anomaly_detected BOOLEAN NOT NULL DEFAULT FALSE,
    severity TEXT NOT NULL,
    risk_policy_version TEXT,
    classification_probabilities JSONB,
    feature_attribution JSONB,
    rationale TEXT,
    model_version TEXT,
    feature_schema_version TEXT,
    detection_method TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    supersedes_id UUID,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_findings__packages FOREIGN KEY (package_id) REFERENCES analytics.findings_packages(package_id) ON DELETE RESTRICT,
    CONSTRAINT fk_findings__acquisitions FOREIGN KEY (acquisition_id) REFERENCES acquisition.acquisitions(acquisition_id) ON DELETE RESTRICT,
    CONSTRAINT ck_findings__decision_state CHECK (decision_state IN ('BENIGN', 'ANOMALOUS', 'SUSPICIOUS_ACTIVITY', 'HIGH_CONFIDENCE_ACTIVITY')),
    CONSTRAINT ck_findings__risk CHECK (risk_score >= 0.0 AND risk_score <= 1.0),
    CONSTRAINT ck_findings__conf CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CONSTRAINT ck_findings__anomaly CHECK (anomaly_score >= 0.0 AND anomaly_score <= 1.0),
    CONSTRAINT ck_findings__severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

CREATE TABLE analytics.finding_flow_links (
    finding_id UUID NOT NULL,
    flow_id UUID NOT NULL,
    PRIMARY KEY (finding_id, flow_id),
    CONSTRAINT fk_finding_flow__findings FOREIGN KEY (finding_id) REFERENCES analytics.findings(finding_id) ON DELETE RESTRICT,
    CONSTRAINT fk_finding_flow__flows FOREIGN KEY (flow_id) REFERENCES intelligence.flows(flow_id) ON DELETE RESTRICT
);

CREATE TABLE analytics.finding_event_links (
    finding_id UUID NOT NULL,
    event_id UUID NOT NULL,
    PRIMARY KEY (finding_id, event_id),
    CONSTRAINT fk_finding_event__findings FOREIGN KEY (finding_id) REFERENCES analytics.findings(finding_id) ON DELETE RESTRICT,
    CONSTRAINT fk_finding_event__events FOREIGN KEY (event_id) REFERENCES intelligence.protocol_events(event_id) ON DELETE RESTRICT
);

CREATE TABLE analytics.finding_artifact_links (
    finding_id UUID NOT NULL,
    artifact_id UUID NOT NULL,
    PRIMARY KEY (finding_id, artifact_id),
    CONSTRAINT fk_finding_artifact__findings FOREIGN KEY (finding_id) REFERENCES analytics.findings(finding_id) ON DELETE RESTRICT,
    CONSTRAINT fk_finding_artifact__artifacts FOREIGN KEY (artifact_id) REFERENCES intelligence.artifacts(artifact_id) ON DELETE RESTRICT
);

-- 5. IDENTITY SCHEMA (isolated)
CREATE TABLE identity.users (
    user_id UUID PRIMARY KEY,
    username TEXT NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    CONSTRAINT uq_users__username UNIQUE (username),
    CONSTRAINT uq_users__email UNIQUE (email),
    CONSTRAINT ck_users__role CHECK (role IN ('administrator', 'investigator', 'analyst'))
);

-- 6. INVESTIGATION SCHEMA
CREATE TABLE investigation.investigation_cases (
    case_id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    priority TEXT,
    trigger_type TEXT NOT NULL,
    trigger_description TEXT,
    external_case_id TEXT,
    external_system TEXT,
    reported_by TEXT,
    investigation_goals TEXT[],
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ,
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_cases__status CHECK (status IN ('open', 'investigating', 'review', 'closed')),
    CONSTRAINT ck_cases__priority CHECK (priority IN ('low', 'medium', 'high', 'critical'))
);

CREATE TABLE investigation.entities (
    entity_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    entity_type TEXT NOT NULL,
    label TEXT NOT NULL,
    value TEXT,
    attributes JSONB,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_entities__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT ck_entities__type CHECK (entity_type IN ('host', 'user', 'service', 'network', 'domain', 'external_ip'))
);

CREATE TABLE investigation.relationships (
    relationship_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    source_entity_id UUID NOT NULL,
    target_entity_id UUID NOT NULL,
    relationship_type TEXT NOT NULL,
    strength FLOAT,
    attributes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_relationships__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT fk_relationships__source FOREIGN KEY (source_entity_id) REFERENCES investigation.entities(entity_id) ON DELETE RESTRICT,
    CONSTRAINT fk_relationships__target FOREIGN KEY (target_entity_id) REFERENCES investigation.entities(entity_id) ON DELETE RESTRICT,
    CONSTRAINT ck_rel__strength CHECK (strength >= 0.0 AND strength <= 1.0)
);

CREATE TABLE investigation.behaviors (
    behavior_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    behavior_type TEXT NOT NULL,
    label TEXT NOT NULL,
    confidence FLOAT,
    attributes JSONB,
    first_observed TIMESTAMPTZ,
    last_observed TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_behaviors__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT ck_behaviors__conf CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

CREATE TABLE investigation.attack_chains (
    attack_chain_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    title TEXT,
    summary TEXT,
    stages JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finalized_at TIMESTAMPTZ,
    CONSTRAINT uq_attack_chains__case_id UNIQUE (case_id),
    CONSTRAINT fk_attack_chains__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT
);

CREATE TABLE investigation.mitre_mappings (
    mitre_mapping_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    attack_chain_id UUID,
    technique_id TEXT NOT NULL,
    tactic TEXT NOT NULL,
    technique_name TEXT,
    attack_version TEXT,
    justification TEXT,
    confidence FLOAT,
    mapped_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_mitre__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT fk_mitre__chains FOREIGN KEY (attack_chain_id) REFERENCES investigation.attack_chains(attack_chain_id) ON DELETE RESTRICT,
    CONSTRAINT ck_mitre__conf CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

CREATE TABLE investigation.timeline_events (
    timeline_event_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    entity_id UUID,
    behavior_id UUID,
    finding_id UUID,
    attributes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_timeline__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT fk_timeline__entities FOREIGN KEY (entity_id) REFERENCES investigation.entities(entity_id) ON DELETE RESTRICT,
    CONSTRAINT fk_timeline__behaviors FOREIGN KEY (behavior_id) REFERENCES investigation.behaviors(behavior_id) ON DELETE RESTRICT
);

-- Investigation Links
CREATE TABLE investigation.relationship_finding_links (
    relationship_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    PRIMARY KEY (relationship_id, finding_id),
    CONSTRAINT fk_rel_finding__rel FOREIGN KEY (relationship_id) REFERENCES investigation.relationships(relationship_id) ON DELETE RESTRICT,
    CONSTRAINT fk_rel_finding__finding FOREIGN KEY (finding_id) REFERENCES analytics.findings(finding_id) ON DELETE RESTRICT
);

CREATE TABLE investigation.entity_artifact_links (
    entity_id UUID NOT NULL,
    artifact_id UUID NOT NULL,
    PRIMARY KEY (entity_id, artifact_id),
    CONSTRAINT fk_entity_art__entities FOREIGN KEY (entity_id) REFERENCES investigation.entities(entity_id) ON DELETE RESTRICT,
    CONSTRAINT fk_entity_art__artifacts FOREIGN KEY (artifact_id) REFERENCES intelligence.artifacts(artifact_id) ON DELETE RESTRICT
);

CREATE TABLE investigation.behavior_finding_links (
    behavior_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    PRIMARY KEY (behavior_id, finding_id),
    CONSTRAINT fk_beh_finding__behaviors FOREIGN KEY (behavior_id) REFERENCES investigation.behaviors(behavior_id) ON DELETE RESTRICT,
    CONSTRAINT fk_beh_finding__findings FOREIGN KEY (finding_id) REFERENCES analytics.findings(finding_id) ON DELETE RESTRICT
);

CREATE TABLE investigation.mitre_finding_links (
    mitre_mapping_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    PRIMARY KEY (mitre_mapping_id, finding_id),
    CONSTRAINT fk_mitre_finding__mitre FOREIGN KEY (mitre_mapping_id) REFERENCES investigation.mitre_mappings(mitre_mapping_id) ON DELETE RESTRICT,
    CONSTRAINT fk_mitre_finding__findings FOREIGN KEY (finding_id) REFERENCES analytics.findings(finding_id) ON DELETE RESTRICT
);

CREATE TABLE analytics.case_finding_links (
    case_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    role TEXT,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, finding_id),
    CONSTRAINT fk_case_finding__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT fk_case_finding__findings FOREIGN KEY (finding_id) REFERENCES analytics.findings(finding_id) ON DELETE RESTRICT
);

CREATE TABLE acquisition.case_acquisition_links (
    case_id UUID NOT NULL,
    acquisition_id UUID NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, acquisition_id),
    CONSTRAINT fk_case_acq__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT fk_case_acq__acquisitions FOREIGN KEY (acquisition_id) REFERENCES acquisition.acquisitions(acquisition_id) ON DELETE RESTRICT
);

-- 7. IDENTITY (case access)
CREATE TABLE identity.case_access (
    case_id UUID NOT NULL,
    user_id UUID NOT NULL,
    access_level TEXT NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by UUID NOT NULL,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (case_id, user_id),
    CONSTRAINT fk_access__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE CASCADE,
    CONSTRAINT fk_access__users FOREIGN KEY (user_id) REFERENCES identity.users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_access__granted_by FOREIGN KEY (granted_by) REFERENCES identity.users(user_id) ON DELETE RESTRICT,
    CONSTRAINT ck_access__level CHECK (access_level IN ('read', 'write', 'admin'))
);

-- 8. CUSTODY SCHEMA
CREATE TABLE custody.evidence_items (
    evidence_item_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    evidence_id UUID,
    label TEXT NOT NULL,
    description TEXT,
    evidence_type TEXT NOT NULL,
    minio_bucket TEXT,
    object_key TEXT,
    sha256 CHAR(64),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    registered_by UUID,
    CONSTRAINT fk_evidence_items__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT fk_evidence_items__evidence FOREIGN KEY (evidence_id) REFERENCES acquisition.evidence(evidence_id) ON DELETE RESTRICT,
    CONSTRAINT ck_evidence_items__type CHECK (evidence_type IN ('pcap', 'pcapng', 'log_file', 'report', 'exported_session', 'analyst_note'))
);

CREATE TABLE custody.custody_events (
    custody_event_id UUID PRIMARY KEY,
    evidence_item_id UUID NOT NULL,
    action TEXT NOT NULL,
    actor_id UUID,
    actor_name TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes TEXT,
    metadata JSONB,
    CONSTRAINT fk_custody_events__items FOREIGN KEY (evidence_item_id) REFERENCES custody.evidence_items(evidence_item_id) ON DELETE RESTRICT
);

CREATE TABLE custody.reports (
    report_id UUID PRIMARY KEY,
    case_id UUID NOT NULL,
    report_type TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    title TEXT,
    minio_bucket TEXT NOT NULL,
    object_key TEXT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    format TEXT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    generated_by UUID,
    CONSTRAINT uq_reports__object_key UNIQUE (object_key),
    CONSTRAINT fk_reports__cases FOREIGN KEY (case_id) REFERENCES investigation.investigation_cases(case_id) ON DELETE RESTRICT,
    CONSTRAINT ck_reports__format CHECK (format IN ('pdf', 'json', 'html', 'zip'))
);

-- 9. AUDIT SCHEMA
CREATE TABLE audit.audit_events (
    audit_event_id UUID PRIMARY KEY,
    actor_id UUID,
    actor_name TEXT,
    action TEXT NOT NULL,
    target_entity_type TEXT,
    target_entity_id TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_ip INET,
    session_id TEXT,
    result TEXT NOT NULL,
    metadata JSONB,
    CONSTRAINT ck_audit__result CHECK (result IN ('success', 'failure', 'denied'))
);

-- 10. INDEXES
CREATE INDEX ix_flows__acq ON intelligence.flows (acquisition_id);
CREATE INDEX ix_flows__src_ip ON intelligence.flows (src_ip);
CREATE INDEX ix_flows__dst_ip ON intelligence.flows (dst_ip);
CREATE INDEX ix_flows__acq_time ON intelligence.flows (acquisition_id, timestamp);

CREATE INDEX ix_events__flow ON intelligence.protocol_events (flow_id);
CREATE INDEX ix_events__flow_time ON intelligence.protocol_events (flow_id, timestamp);
CREATE INDEX ix_events__proto_data ON intelligence.protocol_events USING GIN (protocol_data);

CREATE INDEX ix_artifacts__value ON intelligence.artifacts (value);

CREATE INDEX ix_findings__acq_seen ON analytics.findings (acquisition_id, detected_at);
CREATE INDEX ix_findings__type ON analytics.findings (activity);
CREATE INDEX ix_findings__supersedes ON analytics.findings (supersedes_id);

CREATE INDEX ix_timeline__case_time ON investigation.timeline_events (case_id, event_timestamp);
CREATE INDEX ix_timeline__finding ON investigation.timeline_events (finding_id);

CREATE INDEX ix_entities__case ON investigation.entities (case_id);
CREATE INDEX ix_rel__case_src ON investigation.relationships (case_id, source_entity_id);

CREATE INDEX ix_custody__ev_time ON custody.custody_events (evidence_item_id, occurred_at);

CREATE INDEX ix_audit__target ON audit.audit_events (target_entity_id);
''')


def downgrade() -> None:
    """Downgrade schema."""
    op.execute('''
DROP SCHEMA audit CASCADE;
DROP SCHEMA custody CASCADE;
DROP SCHEMA investigation CASCADE;
DROP SCHEMA identity CASCADE;
DROP SCHEMA analytics CASCADE;
DROP SCHEMA intelligence CASCADE;
DROP SCHEMA acquisition CASCADE;
''')
