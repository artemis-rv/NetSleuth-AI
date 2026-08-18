"""
backend/app/engines/packet_intelligence/zeek/storage.py
-------------------------------------------------------
Synchronous MinIO Object Storage abstraction for the Zeek Engine boundary.
Used within synchronous execution paths (e.g. executor threads) where
asyncio event loops should be avoided.
"""

import os
from contextlib import contextmanager
from typing import Iterator

import boto3
import botocore.exceptions

from app.config import settings
from .errors import ZeekRunnerError, ZeekRunnerErrorCode


class ZeekStorage:
    """Synchronous MinIO storage for generated Zeek logs."""

    def __init__(self) -> None:
        endpoint = settings.minio_endpoint
        if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
            endpoint = f"http://{endpoint}"
            
        self.endpoint_url = os.environ.get("MINIO_URL", endpoint)
        self.access_key = settings.minio_root_user
        self.secret_key = settings.minio_root_password
        self.bucket_name = settings.minio_bucket_zeek

        self.client = boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
        )

    def _ensure_bucket(self) -> None:
        """Ensure the target bucket exists before writing."""
        try:
            self.client.head_bucket(Bucket=self.bucket_name)
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code == "404" or error_code == "NoSuchBucket":
                try:
                    self.client.create_bucket(Bucket=self.bucket_name)
                except Exception as inner_exc:
                    raise ZeekRunnerError(
                        ZeekRunnerErrorCode.OUTPUT_DIR_ERROR,
                        f"Failed to create bucket {self.bucket_name}: {inner_exc}",
                    ) from inner_exc
            else:
                raise ZeekRunnerError(
                    ZeekRunnerErrorCode.OUTPUT_DIR_ERROR,
                    f"Failed to access bucket {self.bucket_name}: {exc}",
                ) from exc
        except Exception as exc:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.OUTPUT_DIR_ERROR,
                f"Failed to access MinIO for bucket {self.bucket_name}: {exc}",
            ) from exc

    def upload_file(self, file_path: str | os.PathLike, object_key: str) -> None:
        """Upload a local file to MinIO."""
        self._ensure_bucket()
        try:
            self.client.upload_file(str(file_path), self.bucket_name, object_key)
        except Exception as exc:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.OUTPUT_DIR_ERROR,
                f"Failed to upload Zeek log to MinIO at {object_key}: {exc}",
            ) from exc

    @contextmanager
    def stream_file(self, object_key: str) -> Iterator[Iterator[str]]:
        """Stream an object from MinIO and yield its decoded lines line-by-line."""
        try:
            response = self.client.get_object(Bucket=self.bucket_name, Key=object_key)
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code == "NoSuchKey":
                raise FileNotFoundError(f"Object {object_key} not found in bucket {self.bucket_name}")
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.OUTPUT_DIR_ERROR,
                f"Failed to stream Zeek log from MinIO at {object_key}: {exc}",
            ) from exc
            
        def decode_lines(streaming_body) -> Iterator[str]:
            for line in streaming_body.iter_lines(keepends=False):
                if line:
                    yield line.decode("utf-8", errors="replace")

        try:
            yield decode_lines(response["Body"])
        finally:
            response["Body"].close()
