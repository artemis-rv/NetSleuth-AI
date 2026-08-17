import pytest
import uuid
import datetime
from sqlalchemy.exc import IntegrityError
import asyncio

from app.persistence.database import engine
from app.persistence.transactions.uow import UnitOfWork
from app.persistence.models import AcquisitionModel, FlowModel
from app.persistence.repositories import AcquisitionRepository, FlowRepository

def generate_sha256():
    return uuid.uuid4().hex + uuid.uuid4().hex

@pytest.mark.asyncio
async def test_insert_and_read():
    uow = UnitOfWork()
    acq_id = uuid.uuid4()
    
    async with uow:
        repo = uow.get_repository(AcquisitionRepository)
        acq = AcquisitionModel(
            acquisition_id=acq_id,
            file_name="test.pcap",
            file_size=1024,
            sha256=generate_sha256(),
            format="pcap",
            source_type="pcap",
            status="complete"
        )
        await repo.create(acq)
        
    async with uow:
        repo = uow.get_repository(AcquisitionRepository)
        fetched = await repo.get(acq_id)
        assert fetched is not None
        assert fetched.file_name == "test.pcap"

@pytest.mark.asyncio
async def test_batch_insert_and_types():
    uow = UnitOfWork()
    acq_id = uuid.uuid4()
    
    async with uow:
        acq_repo = uow.get_repository(AcquisitionRepository)
        await acq_repo.create(AcquisitionModel(
            acquisition_id=acq_id,
            file_name="batch.pcap",
            sha256=generate_sha256(),
            format="pcap",
            source_type="pcap",
            status="complete"
        ))
        
        flow_repo = uow.get_repository(FlowRepository)
        flows = []
        for i in range(5):
            flows.append(FlowModel(
                flow_id=uuid.uuid4(),
                zeek_uid=f"zeek_{i}",
                acquisition_id=acq_id,
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                src_ip="192.168.1.100",
                src_port=50000 + i,
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="udp",
                service="dns",
                provenance={"tool": "zeek"}
            ))
        await flow_repo.bulk_create(flows)
    
    async with uow:
        flow_repo = uow.get_repository(FlowRepository)
        fetched_flow = await flow_repo.get(flows[0].flow_id)
        assert fetched_flow is not None

@pytest.mark.asyncio
async def test_transaction_rollback():
    uow = UnitOfWork()
    acq_id = uuid.uuid4()
    
    try:
        async with uow:
            repo = uow.get_repository(AcquisitionRepository)
            await repo.create(AcquisitionModel(
                acquisition_id=acq_id,
                file_name="fail.pcap",
                sha256=generate_sha256(),
                format="pcap",
                source_type="pcap",
                status="complete"
            ))
            raise ValueError("Simulated failure")
    except ValueError:
        pass
        
    async with uow:
        repo = uow.get_repository(AcquisitionRepository)
        fetched = await repo.get(acq_id)
        assert fetched is None 

@pytest.mark.asyncio
async def test_fk_and_unique_constraints():
    uow = UnitOfWork()
    
    try:
        async with uow:
            flow_repo = uow.get_repository(FlowRepository)
            await flow_repo.bulk_create([FlowModel(
                flow_id=uuid.uuid4(), zeek_uid="zeek_orphan",
                acquisition_id=uuid.uuid4(), 
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                src_ip="192.168.1.1", src_port=123, dst_ip="1.1.1.1", dst_port=80, protocol="tcp", service="http"
            )])
        pytest.fail("Should have raised IntegrityError (FK constraint)")
    except IntegrityError:
        pass 
        
    acq_id = uuid.uuid4()
    shared_hash = generate_sha256()
    
    async with uow:
        acq_repo = uow.get_repository(AcquisitionRepository)
        await acq_repo.create(AcquisitionModel(
            acquisition_id=acq_id, file_name="first.pcap", sha256=shared_hash,
            format="pcap", source_type="pcap", status="complete"
        ))
        
    try:
        async with uow:
            acq_repo = uow.get_repository(AcquisitionRepository)
            await acq_repo.create(AcquisitionModel(
                acquisition_id=uuid.uuid4(), file_name="second.pcap", sha256=shared_hash,
                format="pcap", source_type="pcap", status="complete"
            ))
        pytest.fail("Should have raised IntegrityError (Unique constraint)")
    except IntegrityError:
        pass

@pytest.mark.asyncio
async def test_restrict_delete():
    uow = UnitOfWork()
    acq_id = uuid.uuid4()
    
    async with uow:
        acq_repo = uow.get_repository(AcquisitionRepository)
        await acq_repo.create(AcquisitionModel(
            acquisition_id=acq_id, file_name="delete.pcap", sha256=generate_sha256(),
            format="pcap", source_type="pcap", status="complete"
        ))
        flow_repo = uow.get_repository(FlowRepository)
        await flow_repo.bulk_create([FlowModel(
            flow_id=uuid.uuid4(), zeek_uid="zeek_delete", acquisition_id=acq_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc),
            src_ip="10.0.0.1", src_port=123, dst_ip="10.0.0.2", dst_port=80, protocol="tcp", service="http"
        )])
        
    try:
        async with uow:
            acq = await uow.session.get(AcquisitionModel, acq_id)
            await uow.session.delete(acq)
        pytest.fail("Should have raised IntegrityError")
    except IntegrityError:
        pass
