from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.persistence.models.analytics_models import FindingsPackageModel, FindingModel, ModelRegistryModel

class FindingsPackageRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, package: FindingsPackageModel) -> FindingsPackageModel:
        from sqlalchemy.dialects.postgresql import insert
        stmt = insert(FindingsPackageModel).values(
            package_id=package.package_id,
            acquisition_id=package.acquisition_id,
            source_package_id=package.source_package_id,
            analysis_engine_version=package.analysis_engine_version,
            feature_schema_version=package.feature_schema_version,
            anomaly_model_version=package.anomaly_model_version,
            classifier_model_version=package.classifier_model_version,
            findings_count=package.findings_count,
            created_at=package.created_at
        ).on_conflict_do_nothing()
        await self.session.execute(stmt)
        await self.session.flush()
        return package

    async def get(self, package_id: UUID) -> Optional[FindingsPackageModel]:
        stmt = select(FindingsPackageModel).where(FindingsPackageModel.package_id == package_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

class FindingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, findings: List[FindingModel]) -> None:
        if not findings:
            return
        from sqlalchemy.dialects.postgresql import insert
        for finding in findings:
            stmt = insert(FindingModel).values(
                finding_id=finding.finding_id,
                package_id=finding.package_id,
                acquisition_id=finding.acquisition_id,
                activity=finding.activity,
                decision_state=finding.decision_state,
                risk_score=finding.risk_score,
                confidence=finding.confidence,
                anomaly_score=finding.anomaly_score,
                anomaly_detected=finding.anomaly_detected,
                severity=finding.severity,
                risk_policy_version=finding.risk_policy_version,
                classification_probabilities=finding.classification_probabilities,
                feature_attribution=finding.feature_attribution,
                rationale=finding.rationale,
                model_version=finding.model_version,
                feature_schema_version=finding.feature_schema_version,
                detection_method=finding.detection_method,
                version=finding.version,
                supersedes_id=finding.supersedes_id,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                detected_at=finding.detected_at
            ).on_conflict_do_nothing()
            await self.session.execute(stmt)
        await self.session.flush()

    async def get(self, finding_id: UUID) -> Optional[FindingModel]:
        stmt = select(FindingModel).where(FindingModel.finding_id == finding_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(
        self,
        case_id: UUID,
        skip: int = 0,
        limit: int = 50,
        activity: Optional[str] = None,
        decision_state: Optional[str] = None,
        min_risk: Optional[float] = None
    ) -> List[FindingModel]:
        from app.persistence.models.investigation_models import case_acquisition_links
        
        stmt = select(FindingModel).join(
            case_acquisition_links,
            FindingModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if activity:
            stmt = stmt.where(FindingModel.activity == activity)
        if decision_state:
            stmt = stmt.where(FindingModel.decision_state == decision_state)
        if min_risk is not None:
            stmt = stmt.where(FindingModel.risk_score >= min_risk)
            
        stmt = stmt.order_by(FindingModel.detected_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
        
    async def count_by_case(
        self,
        case_id: UUID,
        activity: Optional[str] = None,
        decision_state: Optional[str] = None,
        min_risk: Optional[float] = None
    ) -> int:
        from app.persistence.models.investigation_models import case_acquisition_links
        from sqlalchemy import func
        
        stmt = select(func.count(FindingModel.finding_id)).join(
            case_acquisition_links,
            FindingModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if activity:
            stmt = stmt.where(FindingModel.activity == activity)
        if decision_state:
            stmt = stmt.where(FindingModel.decision_state == decision_state)
        if min_risk is not None:
            stmt = stmt.where(FindingModel.risk_score >= min_risk)
            
        result = await self.session.execute(stmt)
        return result.scalar_one()

class ModelRegistryRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, registry: ModelRegistryModel) -> ModelRegistryModel:
        self.session.add(registry)
        await self.session.flush()
        return registry

    async def get(self, model_id: UUID) -> Optional[ModelRegistryModel]:
        stmt = select(ModelRegistryModel).where(ModelRegistryModel.model_id == model_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
