import aioboto3
import os
from contextlib import asynccontextmanager
from typing import Optional, Tuple

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

    async def verify_evidence_integrity(self, object_key: str, expected_sha256: str) -> tuple[bool, Optional[str]]:
        """Download object to stream and verify SHA-256 matches expected."""
        import hashlib
        import botocore.exceptions
        
        try:
            sha256_hash = hashlib.sha256()
            async with self.get_client() as s3:
                response = await s3.get_object(Bucket=self.bucket_name, Key=object_key)
                async with response["Body"] as stream:
                    while chunk := await stream.read(8192):
                        sha256_hash.update(chunk)
            
            observed = sha256_hash.hexdigest()
            return observed == expected_sha256, observed
        except botocore.exceptions.ClientError:
            return False, None
