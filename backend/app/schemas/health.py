"""Health check schemas adhering to specs/API_CONTRACT.md and specs/PRD.md."""

from datetime import datetime
from enum import Enum
from typing import Dict, Optional
from pydantic import BaseModel, Field


class ServiceStatus(str, Enum):
    """Overall service status."""
    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class DependencyStatus(str, Enum):
    """Integration dependency status per FR-005."""
    CONNECTED = "connected"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"


class DependencyHealth(BaseModel):
    """Health check outcome for an individual upstream dependency."""
    status: DependencyStatus = Field(..., description="Connection status")
    message: str = Field(..., description="Safe diagnostic message without secrets")
    latency_ms: Optional[float] = Field(default=None, description="Check probe latency in milliseconds")


class HealthLiveResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="ok", description="Process liveness state")


class HealthReadyResponse(BaseModel):
    """Readiness probe response with real dependency statuses."""
    status: ServiceStatus = Field(..., description="Overall readiness status")
    dependencies: Dict[str, DependencyHealth] = Field(
        ...,
        description="Individual status for Wazuh API, OpenSearch, and Ollama",
    )
    retrieved_at: datetime = Field(..., description="Timestamp of probe execution in UTC")
    request_id: str = Field(..., description="Correlation request ID")
