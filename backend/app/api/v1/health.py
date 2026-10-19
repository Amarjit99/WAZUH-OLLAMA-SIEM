"""Health check API endpoints conforming to specs/API_CONTRACT.md."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, status

from app.core.config import Settings, get_settings
from app.schemas.health import HealthLiveResponse, HealthReadyResponse, ServiceStatus
from app.services.health_service import HealthService

router = APIRouter(prefix="/health", tags=["Health"])


def get_health_service(settings: Settings = Depends(get_settings)) -> HealthService:
    """Dependency injection for HealthService."""
    return HealthService(settings=settings)


@router.get("/live", response_model=HealthLiveResponse, summary="Process liveness probe")
async def health_live() -> HealthLiveResponse:
    """Returns 200 OK as long as the backend server process is operational."""
    return HealthLiveResponse(status="ok")


@router.get("/ready", response_model=HealthReadyResponse, summary="Dependency readiness probe")
async def health_ready(
    request: Request,
    response: Response,
    service: HealthService = Depends(get_health_service),
) -> HealthReadyResponse:
    """Probes upstream dependencies truthfully and returns their real operational status.

    HTTP 200 if OK or DEGRADED, HTTP 503 if any required dependency is UNAVAILABLE.
    """
    req_id = getattr(request.state, "request_id", "unknown")
    overall_status, dependencies = await service.check_all()

    # If any required service is unavailable, set 503 Service Unavailable per API contract
    if overall_status == ServiceStatus.UNAVAILABLE:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthReadyResponse(
        status=overall_status,
        dependencies=dependencies,
        retrieved_at=datetime.now(timezone.utc),
        request_id=req_id,
    )
