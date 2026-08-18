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
    env      = settings.app_env

LOCAL DEVELOPMENT:
    Values are sourced from the .env file loaded by Docker Compose or local shell.
    Do NOT hard-code credentials here.

PRODUCTION:
    Inject environment variables via your deployment mechanism (e.g. Kubernetes
    secrets, cloud secret manager, etc.).

SCOPE:
    This module establishes the configuration CONTRACT for the application layer,
    MinIO connectivity, and database access.
"""

import os
from typing import List


class _Settings:
    """
    Centralised configuration for NetSleuth-AI.

    All values are read from environment variables at attribute access time
    to support test patching via os.environ.
    """

    # -------------------------------------------------------------------------
    # Application Layer
    # -------------------------------------------------------------------------

    @property
    def app_name(self) -> str:
        """Application name."""
        return os.environ.get("APP_NAME", "NetSleuth-AI")

    @property
    def app_version(self) -> str:
        """Application version."""
        return os.environ.get("APP_VERSION", "1.0.0")

    @property
    def app_env(self) -> str:
        """
        Application deployment environment: development, staging, production, test.

        Set via: APP_ENV or APPLICATION_ENV
        Default: ``development``
        """
        return os.environ.get("APP_ENV", os.environ.get("APPLICATION_ENV", "development"))

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.app_env.lower() in ("production", "prod")

    @property
    def api_v1_prefix(self) -> str:
        """Public API v1 route prefix."""
        return os.environ.get("API_V1_PREFIX", "/api/v1")

    @property
    def log_level(self) -> str:
        """Logging verbosity level."""
        return os.environ.get("LOG_LEVEL", "INFO").upper()

    @property
    def cors_origins(self) -> List[str]:
        """
        Allowed CORS origins.

        In production, wildcard (*) is forbidden and falls back to an empty list
        unless explicitly declared with trusted domains.
        Set via: CORS_ORIGINS (comma-separated string)
        """
        raw = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173")
        origins = [o.strip() for o in raw.split(",") if o.strip()]
        if self.is_production:
            # Enforce security: eliminate any wildcard in production
            return [o for o in origins if o != "*"]
        return origins

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------

    @property
    def database_url(self) -> str:
        """
        PostgreSQL Async connection URL.

        Set via: DATABASE_URL
        """
        url = os.environ.get("DATABASE_URL")
        if not url and not self.is_production:
            url = "postgresql+asyncpg://postgres:postgres@127.0.0.1:15432/netsleuth"
        if not url:
            raise ValueError("DATABASE_URL must be set in production")
        return url

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
        return os.environ.get("MINIO_ENDPOINT", "localhost:9000")

    @property
    def minio_root_user(self) -> str:
        """
        MinIO root/admin username.

        Set via: MINIO_ROOT_USER
        """
        user = os.environ.get("MINIO_ROOT_USER")
        if not user and not self.is_production:
            user = "minioadmin"
        if not user or (self.is_production and user == "minioadmin"):
            raise ValueError("MINIO_ROOT_USER must be set securely in production")
        return user

    @property
    def minio_root_password(self) -> str:
        """
        MinIO root/admin password.

        Set via: MINIO_ROOT_PASSWORD
        """
        password = os.environ.get("MINIO_ROOT_PASSWORD")
        if not password and not self.is_production:
            password = "minioadmin"
        if not password or (self.is_production and password == "minioadmin"):
            raise ValueError("MINIO_ROOT_PASSWORD must be set securely in production")
        return password

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

    # -------------------------------------------------------------------------
    # Authentication (JWT)
    # -------------------------------------------------------------------------

    @property
    def JWT_SECRET_KEY(self) -> str:
        """
        Secret key for JWT generation. Must be set in environment.
        """
        secret = os.environ.get("JWT_SECRET_KEY")
        if not secret and not self.is_production:
            # fallback for dev if unset, though we should set it in .env
            secret = "dev_secret_key_change_in_production"
        if not secret:
            raise ValueError("JWT_SECRET_KEY must be set")
        return secret

    @property
    def JWT_ALGORITHM(self) -> str:
        """Algorithm used to sign JWT tokens."""
        return os.environ.get("JWT_ALGORITHM", "HS256")

    @property
    def JWT_ACCESS_TOKEN_EXPIRE_MINUTES(self) -> int:
        """Token expiration time in minutes."""
        return int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

    # -------------------------------------------------------------------------
    # LLM / Copilot
    # -------------------------------------------------------------------------

    @property
    def ollama_base_url(self) -> str:
        """
        Base URL for Ollama local inference.
        Set via: OLLAMA_BASE_URL
        Default: http://localhost:11434
        """
        return os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

    @property
    def ollama_model(self) -> str:
        """
        Ollama Model for LLM processing.
        Set via: OLLAMA_MODEL
        Default: qwen2.5-coder:latest
        """
        return os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:latest")



#: Module-level singleton — import this in application code.
settings = _Settings()
