import aioboto3
import os
from contextlib import asynccontextmanager
from typing import Optional, Tuple

class EvidenceStorageService:
    def __init__(self):
        from app.config import settings
        endpoint = settings.minio_endpoint
        if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
            endpoint = f"http://{endpoint}"
        self.endpoint_url = os.getenv("MINIO_URL", endpoint)
        self.access_key = settings.minio_root_user
        self.secret_key = settings.minio_root_password
        self.bucket_name = settings.minio_bucket_evidence
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
                try:
                    await s3.create_bucket(Bucket=self.bucket_name)
                except Exception:
                    pass  # Bucket already exists or created concurrently

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
                content = await response["Body"].read()
                sha256_hash.update(content)
            
            observed = sha256_hash.hexdigest()
            return observed == expected_sha256, observed
        except botocore.exceptions.ClientError:
            return False, None

    @asynccontextmanager
    async def download_evidence_temp(self, object_key: str):
        """
        Securely download an object to a temporary local file via streaming.
        Yields the local file path and automatically cleans it up on exit.
        """
        import tempfile
        import aiofiles
        import botocore.exceptions
        from app.exceptions import InfrastructureError

        # Create a named temporary file (closed so aiofiles can open it)
        fd, temp_path = tempfile.mkstemp(prefix="evidence_", suffix=".pcap")
        os.close(fd)

        try:
            async with self.get_client() as s3:
                try:
                    response = await s3.get_object(Bucket=self.bucket_name, Key=object_key)
                except botocore.exceptions.ClientError as e:
                    raise InfrastructureError(f"Failed to retrieve evidence from MinIO: {str(e)}")

                async with aiofiles.open(temp_path, 'wb') as f:
                    body = response["Body"]
                    while chunk := await body.read(65536):
                        await f.write(chunk)
            
            yield temp_path
            
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
