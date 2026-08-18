"""
backend/app/middleware/request_id.py
-----------------------------------
Request ID / Correlation ID Middleware.

Ensures every HTTP request has an associated X-Request-ID:
1. Reuses incoming X-Request-ID header if provided and valid.
2. Generates a new UUID4 string if missing.
3. Attaches the ID to request.state.request_id.
4. Sets the X-Request-ID header on outgoing HTTP responses.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

REQUEST_ID_HEADER = "X-Request-ID"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that attaches and propagates an X-Request-ID header on every request/response.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming_id = request.headers.get(REQUEST_ID_HEADER)
        request_id = incoming_id.strip() if incoming_id and incoming_id.strip() else str(uuid.uuid4())

        # Store in request state for downstream handlers and logging
        request.state.request_id = request_id

        # Process request
        response = await call_next(request)

        # Inject into response header
        response.headers[REQUEST_ID_HEADER] = request_id
        return response
