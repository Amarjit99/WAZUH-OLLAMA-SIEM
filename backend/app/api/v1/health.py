"""Health check API endpoints conforming to specs/API_CONTRACT.md."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import get_retention_service, verify_api_auth
from app.core.config import Settings, get_settings
from app.schemas.health import (
    AuditVerificationStatusResponse,
    BackupOperationalStatusResponse,
    HealthLiveResponse,
    HealthReadyResponse,
    ServiceStatus,
)
from app.services.backup_scheduler_service import BackupSchedulerService
from app.services.health_service import HealthService
from app.services.retention_service import RetentionService

router = APIRouter(prefix="/health", tags=["Health"])


def get_health_service(settings: Settings = Depends(get_settings)) -> HealthService:
    """Dependency injection for HealthService."""
    return HealthService(settings=settings)


def get_backup_scheduler_service(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> BackupSchedulerService:
    """Retrieve application-level BackupSchedulerService instance."""
    app_svc = getattr(request.app.state, "backup_scheduler_service", None)
    if app_svc is not None:
        return app_svc
    app_svc = BackupSchedulerService(settings=settings)
    request.app.state.backup_scheduler_service = app_svc
    return app_svc


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


@router.get(
    "/backup",
    response_model=BackupOperationalStatusResponse,
    summary="Backup and recovery operational status",
)
async def health_backup(
    request: Request,
    response: Response,
    _auth: bool = Depends(verify_api_auth),
    scheduler_service: BackupSchedulerService = Depends(get_backup_scheduler_service),
) -> BackupOperationalStatusResponse:
    """Operational monitoring probe for database backup encryption, scheduler state, and recovery drill telemetry."""
    status_dict = scheduler_service.get_operational_status()
    if status_dict["status"] == "UNAVAILABLE":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return BackupOperationalStatusResponse(**status_dict)


@router.get(
    "/audit",
    response_model=AuditVerificationStatusResponse,
    summary="Get current audit chain verification telemetry",
)
async def health_audit_status(
    _auth: bool = Depends(verify_api_auth),
    scheduler_service: BackupSchedulerService = Depends(get_backup_scheduler_service),
) -> AuditVerificationStatusResponse:
    """Return the latest recorded audit verification state without triggering expensive re-computation."""
    op_status = scheduler_service.get_operational_status()
    return AuditVerificationStatusResponse(
        status=op_status.get("last_audit_verification_status", "UNVERIFIED"),
        verified_events_count=op_status.get("last_audit_events_verified") or 0,
        active_checkpoint_sequence=None,
        error=op_status.get("last_audit_error"),
        verified_at=op_status.get("last_audit_verification_at") or datetime.now(timezone.utc),
    )


@router.post(
    "/audit/verify",
    response_model=AuditVerificationStatusResponse,
    summary="Trigger on-demand cryptographic audit chain verification",
)
async def health_audit_verify(
    response: Response,
    _auth: bool = Depends(verify_api_auth),
    retention_service: RetentionService = Depends(get_retention_service),
    scheduler_service: BackupSchedulerService = Depends(get_backup_scheduler_service),
) -> AuditVerificationStatusResponse:
    """Execute cryptographic verification of audit event hash chain directly on SQLite database.

    Guarantees:
    - Never fabricates results or returns mock status.
    - Inspects sequential SHA-256 links from genesis or active checkpoint to tip.
    - Records verification timestamp and outcome in operational telemetry.
    """
    async with retention_service.session_factory() as session:
        is_valid, count, err = await retention_service.audit_repo.verify_chain_integrity(session)
        latest_cp = await retention_service.audit_repo.get_latest_checkpoint(session)
        cp_seq = latest_cp.checkpoint_sequence if latest_cp else None

    scheduler_service.record_audit_verification_result(success=is_valid, count=count, error=err)
    if not is_valid:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return AuditVerificationStatusResponse(
        status="VERIFIED" if is_valid else "FAILED",
        verified_events_count=count,
        active_checkpoint_sequence=cp_seq,
        error=err,
        verified_at=datetime.now(timezone.utc),
    )
