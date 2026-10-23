"""Common and Error response schemas adhering to specs/API_CONTRACT.md."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class ErrorCode(str, Enum):
    """Standardized API Error Codes."""
    VALIDATION_ERROR = "VALIDATION_ERROR"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    ANALYSIS_INVALID = "ANALYSIS_INVALID"
    CONFLICT = "CONFLICT"
    INSUFFICIENT_STORAGE = "INSUFFICIENT_STORAGE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ErrorDetail(BaseModel):
    """Inner error payload model."""
    code: ErrorCode = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable safe error message")
    request_id: str = Field(..., description="Correlation request ID")
    details: Optional[Any] = Field(default=None, description="Additional non-sensitive details")


class ErrorResponse(BaseModel):
    """Outer error envelope strictly adhering to API contract."""
    error: ErrorDetail
