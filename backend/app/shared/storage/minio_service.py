import aioboto3
import os
from contextlib import asynccontextmanager

class EvidenceStorageService:
    def __init__(self):
        self.endpoint_url = os.getenv("MINIO_URL", "http://localhost:9000")
        self.access_key = os.getenv("MINIO_ROOT_USER", "minioadmin")
        self.secret_key = os.getenv("MINIO_ROOT_PASSWORD", "minioadmin")
        self.bucket_name = "evidence"
        self.session = aioboto3.Session()

    @asynccontextmanager
    async def get_client(self):
        async with self.session.client(
            's3',
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
        ) as s3:
            yield s3

    async def initialize_bucket(self):
        """Ensure the evidence bucket exists."""
        async with self.get_client() as s3:
            try:
                await s3.head_bucket(Bucket=self.bucket_name)
            except Exception:
                await s3.create_bucket(Bucket=self.bucket_name)

    async def upload_evidence(self, file_path: str, object_key: str) -> None:
        """Upload a local file to MinIO."""
        await self.initialize_bucket()
        async with self.get_client() as s3:
            await s3.upload_file(file_path, self.bucket_name, object_key)
