"""
backend/app/main.py
-------------------
FastAPI Application Entrypoint for NetSleuth-AI.

Intentionally thin application assembly:
- Configures application metadata and lifecycle
- Registers cross-cutting HTTP middleware (Request ID, Security Headers, CORS)
- Registers centralized exception handlers with standardized error envelopes
- Registers health and readiness probes
- Mounts versioned API routers (/api/v1/...)

Does NOT contain raw SQL queries, engine algorithms, or business logic.
"""

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.router import api_router
from app.config import settings
from app.exceptions import ApplicationError
from app.middleware.request_id import REQUEST_ID_HEADER, RequestIdMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.persistence.database import check_health as check_db_health, close_db

logger = logging.getLogger("netsleuth.app")


def _get_request_id(request: Request) -> str:
    """Extract request_id from request state or incoming header."""
    return getattr(request.state, "request_id", request.headers.get(REQUEST_ID_HEADER, "unknown"))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifecycle management (startup and graceful shutdown).
    """
    logger.info("Starting %s v%s in %s environment", settings.app_name, settings.app_version, settings.app_env)
    yield
    logger.info("Shutting down %s...", settings.app_name)
    await close_db()


def create_app() -> FastAPI:
    """
    Application factory for NetSleuth-AI backend.
    """
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="NetSleuth-AI: Forensic Network Investigation System",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # -------------------------------------------------------------------------
    # 1. Register Middleware (LIFO order in Starlette)
    # -------------------------------------------------------------------------
    # Security headers
    application.add_middleware(SecurityHeadersMiddleware)

    # CORS configuration
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[REQUEST_ID_HEADER],
    )

    # Request ID middleware
    application.add_middleware(RequestIdMiddleware)

    def _cors_response(request: Request, status_code: int, content: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None) -> JSONResponse:
        headers = extra_headers or {}
        origin = request.headers.get("origin")
        if origin and (origin in settings.cors_origins or "*" in settings.cors_origins):
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Access-Control-Allow-Methods"] = "*"
            headers["Access-Control-Allow-Headers"] = "*"
        return JSONResponse(status_code=status_code, content=content, headers=headers)

    # -------------------------------------------------------------------------
    # 2. Register Global Exception Handlers (Standardized Error Envelope)
    # -------------------------------------------------------------------------
    @application.exception_handler(ApplicationError)
    async def application_error_handler(request: Request, exc: ApplicationError) -> JSONResponse:
        request_id = _get_request_id(request)
        error_payload: Dict[str, Any] = {
            "code": exc.error_code,
            "message": exc.message,
            "request_id": request_id,
        }
        if exc.details:
            error_payload["details"] = exc.details

        return _cors_response(
            request=request,
            status_code=exc.status_code,
            content={"error": error_payload},
            extra_headers={REQUEST_ID_HEADER: request_id},
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        request_id = _get_request_id(request)
        return _cors_response(
            request=request,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request payload validation failed.",
                    "request_id": request_id,
                    "details": exc.errors(),
                }
            },
            extra_headers={REQUEST_ID_HEADER: request_id},
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        request_id = _get_request_id(request)
        error_code = "HTTP_ERROR"
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            error_code = "RESOURCE_NOT_FOUND"
        elif exc.status_code == status.HTTP_401_UNAUTHORIZED:
            error_code = "UNAUTHORIZED"
        elif exc.status_code == status.HTTP_403_FORBIDDEN:
            error_code = "FORBIDDEN"
        elif exc.status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
            error_code = "METHOD_NOT_ALLOWED"

        return _cors_response(
            request=request,
            status_code=exc.status_code,
            content={
                "error": {
                    "code": error_code,
                    "message": str(exc.detail),
                    "request_id": request_id,
                }
            },
            extra_headers={REQUEST_ID_HEADER: request_id},
        )

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = _get_request_id(request)
        import traceback
        print("GLOBAL EXCEPTION HANDLER CAUGHT AN EXCEPTION:", flush=True)
        traceback.print_exc()
        logger.exception("Unhandled server exception on %s [request_id=%s]: %s", request.url.path, request_id, exc)
        return _cors_response(
            request=request,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected internal server error occurred.",
                    "request_id": request_id,
                }
            },
            extra_headers={REQUEST_ID_HEADER: request_id},
        )

    # -------------------------------------------------------------------------
    # 3. Base Platform Health Endpoints
    # -------------------------------------------------------------------------
    @application.get("/", tags=["System"])
    async def root_welcome() -> Dict[str, str]:
        """Root endpoint: provides system info and docs link."""
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "status": "running",
            "documentation": "/docs"
        }

    @application.get("/health", tags=["System"])
    async def health_check() -> Dict[str, str]:
        """Liveness probe: verifies process is alive."""
        return {"status": "healthy"}

    @application.get("/health/db", tags=["System"])
    async def health_db_check() -> Dict[str, Any]:
        """Database health check."""
        is_healthy = await check_db_health()
        if not is_healthy:
            return JSONResponse(status_code=503, content={"status": "unhealthy", "database": "disconnected"})
        return {"status": "healthy", "database": "connected"}

    @application.get("/health/storage", tags=["System"])
    async def health_storage_check() -> Dict[str, Any]:
        """MinIO / S3 storage health check."""
        try:
            from app.shared.storage.minio_service import EvidenceStorageService
            svc = EvidenceStorageService()
            async with svc.get_client() as s3:
                await s3.list_buckets()
            return {"status": "healthy", "storage": "connected"}
        except Exception as e:
            return JSONResponse(status_code=503, content={"status": "unhealthy", "storage": "disconnected", "error": str(e)})

    @application.get("/ready", tags=["System"])
    async def readiness_check() -> Dict[str, str]:
        """Readiness probe: verifies application is initialized to accept traffic."""
        return {"status": "ready"}

    # -------------------------------------------------------------------------
    # 4. Mount API Routers
    # -------------------------------------------------------------------------
    application.include_router(api_router)

    return application


app = create_app()
