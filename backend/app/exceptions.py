"""
backend/app/exceptions.py
-------------------------
Centralized Application Exception Boundary for NetSleuth-AI.

Defines standard exception classes and error codes.
Ensures uniform error representations without leaking internal stack traces.
"""

from typing import Any, Dict, Optional


class ApplicationError(Exception):
    """
    Base exception for all application-level errors.
    """
    status_code: int = 500
    error_code: str = "INTERNAL_SERVER_ERROR"

    def __init__(
        self,
        message: str = "An internal server error occurred.",
        *,
        error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        if error_code is not None:
            self.error_code = error_code
        if status_code is not None:
            self.status_code = status_code
        self.details = details or {}


class ValidationError(ApplicationError):
    """Raised when client input or payload fails validation."""
    status_code = 422
    error_code = "VALIDATION_ERROR"


class NotFoundError(ApplicationError):
    """Raised when a requested resource does not exist."""
    status_code = 404
    error_code = "RESOURCE_NOT_FOUND"


class ConflictError(ApplicationError):
    """Raised when an operation conflicts with the current resource state."""
    status_code = 409
    error_code = "RESOURCE_CONFLICT"


class UnauthorizedError(ApplicationError):
    """Raised when authentication is missing or invalid."""
    status_code = 401
    error_code = "UNAUTHORIZED"


class ForbiddenError(ApplicationError):
    """Raised when an authenticated entity lacks permission for an action."""
    status_code = 403
    error_code = "FORBIDDEN"


class InfrastructureError(ApplicationError):
    """Raised when an external or infrastructure dependency fails."""
    status_code = 503
    error_code = "INFRASTRUCTURE_UNAVAILABLE"
