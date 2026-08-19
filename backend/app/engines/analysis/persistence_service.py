import uuid
from typing import Optional
from sqlalchemy import insert

from app.contracts.analysis import FindingsPackage, Finding
from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models.analytics_models import (
    FindingsPackageModel, 
    FindingModel,
    finding_flow_links,
    finding_event_links,
    finding_artifact_links
)
from app.persistence.repositories.analytics_repository import FindingsPackageRepository, FindingRepository

class M2PersistenceService:
    def __init__(self):
        # We assume FindingsPackage is passed directly in memory.
        pass

    async def persist_findings_package(self, package: FindingsPackage) -> None:
        """
        Persists an M2 FindingsPackage and all its Findings transactionally.
        """
        uow = UnitOfWork()
        async with uow:
            # 1. Insert FindingsPackageModel
            package_repo = uow.get_repository(FindingsPackageRepository)
            pkg_uuid = uuid.uuid4()
            pkg_model = FindingsPackageModel(
                package_id=pkg_uuid,
                acquisition_id=uuid.UUID(package.acquisition_id),
                source_package_id=package.source_package_id,
                analysis_engine_version=package.analysis_engine_version,
                feature_schema_version=package.feature_schema_version,
                anomaly_model_version=package.anomaly_model_version,
                classifier_model_version=package.classifier_model_version,
                findings_count=len(package.findings),
                created_at=package.analysed_at
            )
            await package_repo.create(pkg_model)

            # 2. Map and Insert Findings
            finding_repo = uow.get_repository(FindingRepository)
            finding_models = []
            
            # Lists for bulk inserting many-to-many relationships
            flow_links_data = []
            event_links_data = []
            artifact_links_data = []

            for finding in package.findings:
                try:
                    f_uuid = uuid.UUID(finding.finding_id)
                except ValueError:
                    f_uuid = uuid.uuid5(uuid.NAMESPACE_OID, finding.finding_id)
                with open('debug_finding.txt', 'a') as f: f.write(f"M2 PERSISTENCE: finding_id={finding.finding_id}, f_uuid={f_uuid}\n")
                
                # Determine classification and anomaly extraction
                class_probs = None
                if finding.classification_result:
                    class_probs = finding.classification_result.class_probabilities
                
                # CRITICAL M2 SEVERITY BRIDGE DOCUMENTATION
                # ---------------------------------------------------------------------------------
                # M2 (Analysis Engine) does NOT determine true investigation severity. 
                # Severity mapping is exclusively owned by M3 (Correlation & Investigation).
                # We hardcode `severity="low"` here SOLELY to satisfy the PostgreSQL DB-6 
                # `analytics.findings` check constraint which requires a non-null severity value.
                # This is a persistence-layer bridge only; it is NOT an analytical conclusion.
                # ---------------------------------------------------------------------------------
                severity = "low"
                
                # Determine detection method
                if finding.classification_result and finding.anomaly_result:
                    detection_method = "hybrid"
                elif finding.classification_result:
                    detection_method = "supervised"
                elif finding.anomaly_result:
                    detection_method = "unsupervised"
                else:
                    detection_method = "unknown"

                # Extract first rationale as the primary rationale
                rationale = None
                if finding.evidence_references and finding.evidence_references[0].rationale:
                    rationale = finding.evidence_references[0].rationale

                f_model = FindingModel(
                    finding_id=f_uuid,
                    package_id=pkg_model.package_id,
                    acquisition_id=uuid.UUID(finding.acquisition_id),
                    activity=finding.activity_class.value,
                    decision_state=finding.decision_state or "SUSPICIOUS_ACTIVITY",
                    risk_score=finding.risk_score,
                    confidence=finding.classification_confidence,
                    anomaly_score=finding.anomaly_score,
                    anomaly_detected=finding.anomaly_detected,
                    severity=severity,
                    classification_probabilities=class_probs,
                    feature_attribution=finding.feature_snapshot,
                    rationale=rationale,
                    model_version=finding.model_version,
                    feature_schema_version=finding.feature_schema_version,
                    detection_method=detection_method,
                    detected_at=finding.created_at
                )
                finding_models.append(f_model)

                # Map Evidence References for bulk M2M inserts
                for ev in finding.evidence_references:
                    for flow_id in ev.flow_ids:
                        flow_links_data.append({"finding_id": f_uuid, "flow_id": uuid.UUID(flow_id)})
                    for event_id in ev.event_ids:
                        event_links_data.append({"finding_id": f_uuid, "event_id": uuid.UUID(event_id)})
                    for artifact_id in ev.artifact_ids:
                        artifact_links_data.append({"finding_id": f_uuid, "artifact_id": uuid.UUID(artifact_id)})

            if finding_models:
                await finding_repo.bulk_create(finding_models)

            # 3. Bulk Insert Many-to-Many Relationships
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            if flow_links_data:
                await uow.session.execute(pg_insert(finding_flow_links).values(flow_links_data).on_conflict_do_nothing())
            if event_links_data:
                await uow.session.execute(pg_insert(finding_event_links).values(event_links_data).on_conflict_do_nothing())
            if artifact_links_data:
                await uow.session.execute(pg_insert(finding_artifact_links).values(artifact_links_data).on_conflict_do_nothing())

