"""Central error handling and exception handlers conforming to specs/API_CONTRACT.md."""

import logging
from typing import Any, Optional
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas.error import ErrorCode, ErrorDetail, ErrorResponse

logger = logging.getLogger("siem.errors")


class AppException(Exception):
    """Base application exception for typed SIEM errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Any] = None,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


class DependencyUnavailableException(AppException):
    """Raised when a required upstream service (Wazuh/OpenSearch/Ollama) is unavailable."""

    def __init__(self, service_name: str, message: str = "Service is unavailable"):
        super().__init__(
            code=ErrorCode.DEPENDENCY_UNAVAILABLE,
            message=f"{service_name}: {message}",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


def _get_request_id(request: Request) -> str:
    """Safely obtain request correlation ID."""
    return getattr(request.state, "request_id", "unknown")


def register_error_handlers(app: FastAPI) -> None:
    """Register custom exception handlers on the FastAPI app."""

    @app.exception_handler(AppException)
    async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
        req_id = _get_request_id(request)
        logger.warning(
            "AppException [%s] (%s): %s (req_id=%s)",
            exc.code.value,
            exc.status_code,
            exc.message,
            req_id,
        )
        payload = ErrorResponse(
            error=ErrorDetail(
                code=exc.code,
                message=exc.message,
                request_id=req_id,
                details=exc.details,
            )
        )
        return JSONResponse(status_code=exc.status_code, content=payload.model_dump())

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        req_id = _get_request_id(request)
        code_map = {
            400: ErrorCode.VALIDATION_ERROR,
            401: ErrorCode.UNAUTHORIZED,
            403: ErrorCode.FORBIDDEN,
            404: ErrorCode.NOT_FOUND,
            409: ErrorCode.CONFLICT,
            429: ErrorCode.RATE_LIMITED,
            503: ErrorCode.DEPENDENCY_UNAVAILABLE,
            504: ErrorCode.UPSTREAM_TIMEOUT,
            507: ErrorCode.INSUFFICIENT_STORAGE,
        }
        error_code = code_map.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
        payload = ErrorResponse(
            error=ErrorDetail(
                code=error_code,
                message=str(exc.detail),
                request_id=req_id,
            )
        )
        return JSONResponse(status_code=exc.status_code, content=payload.model_dump())

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        req_id = _get_request_id(request)
        # Format validation errors safely without echoing raw untrusted payloads
        clean_errors = []
        for err in exc.errors():
            loc = " -> ".join(str(p) for p in err.get("loc", []))
            clean_errors.append(f"{loc}: {err.get('msg', 'invalid value')}")

        payload = ErrorResponse(
            error=ErrorDetail(
                code=ErrorCode.VALIDATION_ERROR,
                message="Request validation failed",
                request_id=req_id,
                details=clean_errors,
            )
        )
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content=payload.model_dump())

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        req_id = _get_request_id(request)
        logger.error("Unhandled server exception (req_id=%s): %s", req_id, str(exc), exc_info=True)
        # Mask internal exception details to prevent secret and stack leakage
        payload = ErrorResponse(
            error=ErrorDetail(
                code=ErrorCode.INTERNAL_ERROR,
                message="An internal server error occurred",
                request_id=req_id,
            )
        )
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=payload.model_dump())
