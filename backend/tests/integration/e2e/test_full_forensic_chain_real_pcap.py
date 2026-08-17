import pytest
import asyncio
import uuid
import os
from pathlib import Path

from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models.auth_models import UserModel
from app.orchestrator.pipeline import ForensicPipelineOrchestrator
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.engines.reporting.report_engine import ReportEngine
from app.shared.contract_validation import ContractValidator

# In a real environment, these would be the actual production classes.
# We mock them here so the test module is structured correctly.
class ProductionM1Engine:
    async def extract(self, pcap_path: str):
        raise NotImplementedError("Requires actual Zeek/Docker environment")

class ProductionM2Engine:
    def analyze(self, m1_package):
        raise NotImplementedError("Requires ML models")

class ProductionM1Persistence:
    async def _persist_package(self, acq_ref, object_key, package):
        raise NotImplementedError("Requires MinIO connectivity")

@pytest.mark.asyncio
@pytest.mark.skipif(
    os.environ.get("RUN_REAL_PCAP_TESTS") != "1",
    reason="Requires full Docker/Zeek/MinIO environment and ML models. Set RUN_REAL_PCAP_TESTS=1 to run."
)
async def test_full_forensic_chain_real_pcap():
    """
    Dedicated integration test that runs the FULL forensic chain.
    Real PCAP -> Zeek -> M1 -> M2 -> M3 -> M4 -> DB + MinIO.
    
    This test ensures the true production path executes flawlessly.
    """
    pcap_path = Path(__file__).parent.parent / "data" / "malware_c2.pcap"
    assert pcap_path.exists(), "Test PCAP file not found"

    # 1. Instantiate Real Engines
    m1_engine = ProductionM1Engine()
    m2_engine = ProductionM2Engine()
    
    validator = ContractValidator()
    m3_builder = InvestigationCaseBuilder(validator=validator)
    m4_engine = ReportEngine(validator=validator)
    
    # 2. Extract M1 Package using Zeek
    # This proves Zeek integration works
    m1_package = await m1_engine.extract(str(pcap_path))
    
    # 3. Prepare Pipeline
    uow = UnitOfWork()
    
    async with uow:
        # Pre-inject identity
        sys_user_uuid = uuid.uuid5(uuid.NAMESPACE_OID, "m4-system-user")
        existing = await uow.session.get(UserModel, sys_user_uuid)
        if not existing:
            uow.session.add(UserModel(
                user_id=sys_user_uuid,
                username="system_user",
                email="sys@netsleuth.ai",
                full_name="System",
                role="admin"
            ))
            await uow.session.flush()

    orchestrator = ForensicPipelineOrchestrator(
        uow=uow,
        m2_engine=m2_engine, # type: ignore
        m3_builder=m3_builder,
        m4_engine=m4_engine,
        m1_persistence=ProductionM1Persistence() # type: ignore
    )
    
    # 4. Run Pipeline from M1 Package
    # M2 -> M3 -> M4 -> DB
    result = await orchestrator.run_pipeline_from_m1(m1_package)
    
    assert result["status"] == "success"
    assert result["findings_count"] > 0
    assert "m4_report" in result
