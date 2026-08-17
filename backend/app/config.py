"""
backend/app/config.py
---------------------
NetSleuth-AI application configuration.

Loads configuration from environment variables.
Uses os.environ for portability without requiring additional dependencies.

Usage:
    from app.config import settings

    endpoint = settings.minio_endpoint
    bucket   = settings.minio_bucket_evidence

LOCAL DEVELOPMENT:
    Values are sourced from the .env file loaded by Docker Compose.
    Do NOT hard-code credentials here.

PRODUCTION:
    Inject environment variables via your deployment mechanism (e.g. Kubernetes
    secrets, cloud secret manager, etc.).

SCOPE:
    This module establishes the configuration CONTRACT for future integration.
    Application-layer MinIO connectivity (SDK, repository, service layer) is
    implemented separately in subsequent phases.
"""

import os


class _Settings:
    """
    Centralised configuration for NetSleuth-AI.

    All values are read from environment variables at attribute access time
    to support test patching via os.environ.
    """

    # -------------------------------------------------------------------------
    # MinIO Object Storage
    # -------------------------------------------------------------------------

    @property
    def minio_endpoint(self) -> str:
        """
        MinIO S3 API endpoint.

        Inside Docker: ``minio:9000``
        From host:     ``localhost:9000``

        Set via: MINIO_ENDPOINT
        """
        return os.environ["MINIO_ENDPOINT"]

    @property
    def minio_root_user(self) -> str:
        """
        MinIO root/admin username.

        Set via: MINIO_ROOT_USER
        """
        return os.environ["MINIO_ROOT_USER"]

    @property
    def minio_root_password(self) -> str:
        """
        MinIO root/admin password.

        Set via: MINIO_ROOT_PASSWORD
        """
        return os.environ["MINIO_ROOT_PASSWORD"]

    @property
    def minio_region(self) -> str:
        """
        MinIO region identifier. MinIO is region-agnostic; used for S3
        API compatibility only.

        Set via: MINIO_REGION
        Default: ``us-east-1``
        """
        return os.environ.get("MINIO_REGION", "us-east-1")

    @property
    def minio_use_ssl(self) -> bool:
        """
        Whether the MinIO connection should use TLS/SSL.

        Set via: MINIO_USE_SSL
        Default: False (local development)
        """
        return os.environ.get("MINIO_USE_SSL", "false").lower() in ("true", "1", "yes")

    # -------------------------------------------------------------------------
    # MinIO Bucket Names
    # -------------------------------------------------------------------------

    @property
    def minio_bucket_evidence(self) -> str:
        """
        Bucket for original PCAP/PCAPNG evidence objects.

        Properties: private, versioned, object-lock capable.
        Set via: MINIO_BUCKET_EVIDENCE
        Default: ``netsleuth-evidence``
        """
        return os.environ.get("MINIO_BUCKET_EVIDENCE", "netsleuth-evidence")

    @property
    def minio_bucket_zeek(self) -> str:
        """
        Bucket for Zeek-generated output files (derived data).

        Set via: MINIO_BUCKET_ZEEK
        Default: ``netsleuth-zeek``
        """
        return os.environ.get("MINIO_BUCKET_ZEEK", "netsleuth-zeek")

    @property
    def minio_bucket_datasets(self) -> str:
        """
        Bucket for ML datasets (raw, processed, manifests).

        Set via: MINIO_BUCKET_DATASETS
        Default: ``netsleuth-datasets``
        """
        return os.environ.get("MINIO_BUCKET_DATASETS", "netsleuth-datasets")

    @property
    def minio_bucket_models(self) -> str:
        """
        Bucket for ML model artifacts (model weights, scalers, metadata).

        Set via: MINIO_BUCKET_MODELS
        Default: ``netsleuth-models``
        """
        return os.environ.get("MINIO_BUCKET_MODELS", "netsleuth-models")

    @property
    def minio_bucket_reports(self) -> str:
        """
        Bucket for generated forensic reports and exports.

        Set via: MINIO_BUCKET_REPORTS
        Default: ``netsleuth-reports``
        """
        return os.environ.get("MINIO_BUCKET_REPORTS", "netsleuth-reports")


#: Module-level singleton — import this in application code.
settings = _Settings()
