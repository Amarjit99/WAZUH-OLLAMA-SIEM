"""Middleware for request correlation and response timing."""

import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Middleware to assign or propagate an X-Request-ID correlation identifier."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()
        
        # Extract or generate correlation ID
        correlation_id = request.headers.get("X-Request-ID")
        if not correlation_id or not correlation_id.strip():
            correlation_id = str(uuid.uuid4())

        request.state.request_id = correlation_id

        # Process the request
        response = await call_next(request)

        # Attach correlation ID and execution time to response
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        response.headers["X-Request-ID"] = correlation_id
        response.headers["X-Response-Time-Ms"] = f"{duration_ms:.2f}"

        return response
