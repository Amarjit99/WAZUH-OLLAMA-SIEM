"""Alerts API router conforming to specs/API_CONTRACT.md and specs/DATA_SCHEMA.md."""

import csv
from datetime import datetime, timedelta, timezone
import io
import ipaddress
import json
import logging
import math
import time
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.core.sanitization import sanitize_csv_formula
from app.db.session import get_session_factory
from app.repositories.audit_repository import AuditRepository

from app.api.deps import (
    get_evidence_service,
    get_investigation_persistence_service,
    get_ollama_client,
    get_opensearch_client,
    verify_api_auth,
)
from app.core.config import Settings, get_settings
from app.core.errors import AppException
from app.schemas.alert import (
    AlertListResponse,
    DataStatus,
    NormalizedAlert,
    PaginationMetadata,
    QueryWindow,
)
from app.schemas.error import ErrorCode
from app.schemas.investigation import InvestigationRequest, InvestigationResult
from app.services.evidence_service import EvidenceService
from app.services.investigation_persistence_service import InvestigationPersistenceService
from app.services.ollama_client import OllamaClient
from app.services.opensearch_client import OpenSearchClient

logger = logging.getLogger("siem.alerts_api")

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
    dependencies=[Depends(verify_api_auth)],
)


def _parse_and_validate_timestamp(ts: Optional[datetime], field_name: str) -> Optional[datetime]:
    """Ensure timestamp is timezone-aware UTC."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


@router.get(
    "",
    response_model=AlertListResponse,
    summary="List normalized security alerts",
    description="Query alerts from OpenSearch within a validated, bounded time window (<= 24h).",
)
async def list_alerts(
    request: Request,
    start_time: Optional[datetime] = Query(
        default=None,
        description="Query window start in ISO 8601 UTC. Defaults to 1 hour before end_time.",
    ),
    end_time: Optional[datetime] = Query(
        default=None,
        description="Query window end in ISO 8601 UTC. Defaults to current UTC time.",
    ),
    severity_min: Optional[int] = Query(
        default=None,
        ge=1,
        le=16,
        description="Minimum Wazuh rule level filter (1-16).",
    ),
    rule_id: Optional[str] = Query(
        default=None,
        max_length=64,
        description="Optional rule ID filter.",
    ),
    host_name: Optional[str] = Query(
        default=None,
        max_length=255,
        description="Optional agent or host name filter.",
    ),
    source_ip: Optional[str] = Query(
        default=None,
        max_length=45,
        description="Optional source IP filter (IPv4 or IPv6 format).",
    ),
    username: Optional[str] = Query(
        default=None,
        max_length=128,
        description="Optional username or user account filter.",
    ),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(default=50, ge=1, le=100, description="Page size (maximum 100)."),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$", description="Sort order by timestamp."),
    settings: Settings = Depends(get_settings),
    opensearch: OpenSearchClient = Depends(get_opensearch_client),
) -> AlertListResponse:
    """Execute bounded, read-only search for normalized security alerts."""
    req_id = getattr(request.state, "request_id", "unknown")
    retrieved_at = datetime.now(timezone.utc)

    # Resolve timestamps
    resolved_end = _parse_and_validate_timestamp(end_time, "end_time") or retrieved_at
    resolved_start = _parse_and_validate_timestamp(start_time, "start_time") or (
        resolved_end - timedelta(hours=settings.DEFAULT_QUERY_WINDOW_HOURS)
    )

    if resolved_start > resolved_end:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="start_time must be earlier than or equal to end_time",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Enforce maximum time window bound
    max_window = timedelta(hours=settings.MAX_QUERY_WINDOW_HOURS)
    if (resolved_end - resolved_start) > max_window:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Query window exceeds maximum allowed limit of {settings.MAX_QUERY_WINDOW_HOURS} hours",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Validate IP format if provided
    if source_ip:
        try:
            ipaddress.ip_address(source_ip.strip())
        except ValueError:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message=f"Invalid source_ip format: '{source_ip}'",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    items, total_count, data_status = await opensearch.search_alerts(
        start_time=resolved_start,
        end_time=resolved_end,
        severity_min=severity_min,
        rule_id=rule_id,
        host_name=host_name,
        source_ip=source_ip,
        username=username,
        page=page,
        page_size=page_size,
        sort_order=sort_order,
    )

    total_pages = math.ceil(total_count / page_size) if total_count > 0 else 0
    has_more = page < total_pages

    pagination = PaginationMetadata(
        page=page,
        page_size=page_size,
        total_items=total_count,
        total_pages=total_pages,
        has_more=has_more,
    )

    query_window = QueryWindow(
        start_time=resolved_start,
        end_time=resolved_end,
    )

    return AlertListResponse(
        items=items,
        pagination=pagination,
        query_window=query_window,
        retrieved_at=retrieved_at,
        data_status=data_status,
        request_id=req_id,
    )


@router.get(
    "/export",
    summary="Export security alerts",
    description="Export filtered normalized security alerts as sanitized CSV or JSON with formula injection protection and audit logging.",
)
async def export_alerts(
    request: Request,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    start_time: Optional[datetime] = Query(None, description="Start timestamp (ISO-8601 UTC)"),
    end_time: Optional[datetime] = Query(None, description="End timestamp (ISO-8601 UTC)"),
    severity_min: Optional[int] = Query(None, ge=0, le=16, description="Minimum rule severity level"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    host_name: Optional[str] = Query(None, description="Filter by agent/host name"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    username: Optional[str] = Query(None, description="Filter by user name"),
    limit: int = Query(500, ge=1, le=1000, description="Maximum alerts to export"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order by timestamp"),
    opensearch: OpenSearchClient = Depends(get_opensearch_client),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Export filtered security alerts as sanitized CSV or JSON with audit logging."""
    req_id = getattr(request.state, "request_id", "req-unknown")
    actor_id = getattr(request.state, "user_id", "local_analyst")
    client_ip = request.client.host if request.client else "127.0.0.1"

    now_utc = datetime.now(timezone.utc)
    resolved_end = _parse_and_validate_timestamp(end_time, "end_time") or now_utc
    resolved_start = _parse_and_validate_timestamp(start_time, "start_time") or (
        resolved_end - timedelta(hours=settings.DEFAULT_QUERY_WINDOW_HOURS)
    )

    if resolved_start >= resolved_end:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="start_time must be strictly before end_time",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    max_window = timedelta(hours=settings.MAX_QUERY_WINDOW_HOURS)
    if (resolved_end - resolved_start) > max_window:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Query window exceeds maximum allowed limit of {settings.MAX_QUERY_WINDOW_HOURS} hours",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if source_ip:
        try:
            ipaddress.ip_address(source_ip.strip())
        except ValueError:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message=f"Invalid source_ip format: '{source_ip}'",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    items, total_count, _ = await opensearch.search_alerts(
        start_time=resolved_start,
        end_time=resolved_end,
        severity_min=severity_min,
        rule_id=rule_id,
        host_name=host_name,
        source_ip=source_ip,
        username=username,
        page=1,
        page_size=limit,
        sort_order=sort_order,
    )

    # Audit the alert export event
    session_factory = get_session_factory()
    audit_repo = AuditRepository()
    async with session_factory() as session:
        async with session.begin():
            await audit_repo.log_event(
                session=session,
                actor_id=actor_id,
                action="ALERTS_EXPORTED",
                resource_type="alerts",
                resource_id="stream",
                outcome="SUCCESS",
                request_id=req_id,
                client_ip=client_ip,
                metadata={
                    "format": format,
                    "count": len(items),
                    "total_available": total_count,
                    "severity_min": severity_min,
                    "rule_id": rule_id,
                },
            )

    if format == "json":
        export_dict = [item.model_dump() for item in items]
        json_content = json.dumps(export_dict, indent=2, default=str)
        return Response(
            content=json_content,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="alerts_export.json"'},
        )

    # format == "csv"
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "Alert ID",
        "Timestamp UTC",
        "Rule ID",
        "Rule Level",
        "Rule Description",
        "Agent ID",
        "Agent Name",
        "Host Name",
        "Source IP",
        "Destination IP",
        "Username",
        "Event Type",
        "Location",
        "Decoder Name",
        "Raw Evidence Ref",
    ])
    for item in items:
        writer.writerow([
            sanitize_csv_formula(item.alert_id),
            item.timestamp.isoformat() if item.timestamp else "",
            sanitize_csv_formula(item.rule_id),
            item.rule_level if item.rule_level is not None else "",
            sanitize_csv_formula(item.rule_description or ""),
            sanitize_csv_formula(item.agent_id or ""),
            sanitize_csv_formula(item.agent_name or ""),
            sanitize_csv_formula(item.host_name or ""),
            sanitize_csv_formula(item.source_ip or ""),
            sanitize_csv_formula(item.destination_ip or ""),
            sanitize_csv_formula(item.username or ""),
            sanitize_csv_formula(item.event_type or ""),
            sanitize_csv_formula(item.location or ""),
            sanitize_csv_formula(item.decoder_name or ""),
            sanitize_csv_formula(item.raw_evidence_ref or ""),
        ])

    return Response(
        content=out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="alerts_export.csv"'},
    )


@router.get(
    "/{alert_id}",
    response_model=NormalizedAlert,
    summary="Get single normalized alert by source ID",
    description="Retrieve an authoritative alert document by its unique source ID.",
)
async def get_alert(
    alert_id: str,
    request: Request,
    opensearch: OpenSearchClient = Depends(get_opensearch_client),
) -> NormalizedAlert:
    """Retrieve an individual alert by its exact stable source document ID."""
    clean_id = alert_id.strip()
    if not clean_id or len(clean_id) > 128:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="Invalid alert ID format",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    alert = await opensearch.get_alert_by_id(clean_id)
    if alert is None:
        raise AppException(
            code=ErrorCode.NOT_FOUND,
            message=f"Alert with ID '{clean_id}' was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    return alert


@router.post(
    "/{alert_id}/investigate",
    response_model=InvestigationResult,
    summary="Investigate alert using local AI inference",
    description="Constructs bounded, sanitized evidence from authoritative SIEM data and performs structured local Ollama analysis.",
)
async def investigate_alert_endpoint(
    alert_id: str,
    request: Request,
    investigation_request: Optional[InvestigationRequest] = None,
    opensearch: OpenSearchClient = Depends(get_opensearch_client),
    evidence_service: EvidenceService = Depends(get_evidence_service),
    ollama: OllamaClient = Depends(get_ollama_client),
    persistence_service: InvestigationPersistenceService = Depends(get_investigation_persistence_service),
) -> InvestigationResult:
    """Execute evidence-grounded AI alert investigation."""
    clean_id = alert_id.strip()
    if not clean_id or len(clean_id) > 128:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="Invalid alert ID format",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # 1. Retrieve authoritative alert
    alert = await opensearch.get_alert_by_id(clean_id)
    if alert is None:
        raise AppException(
            code=ErrorCode.NOT_FOUND,
            message=f"Alert with ID '{clean_id}' was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # 2. Check for in-flight running investigation (HTTP 409 CONFLICT)
    running_inv = await persistence_service.get_running_investigation_for_alert(clean_id)
    if running_inv is not None:
        raise AppException(
            code=ErrorCode.CONFLICT,
            message=f"An investigation is already in progress for alert '{clean_id}'.",
            status_code=status.HTTP_409_CONFLICT,
            details={
                "error_code": "CONCURRENT_INVESTIGATION_RUNNING",
                "investigation_id": running_inv.investigation_id,
                "status": "running",
            },
        )

    # 3. Extract options
    include_related = False
    window_minutes = 30
    max_related = 10
    max_items = 10
    if investigation_request is not None:
        include_related = investigation_request.include_related_events
        window_minutes = investigation_request.correlation_window_minutes
        max_related = investigation_request.max_related_events
        max_items = investigation_request.max_evidence_items

    # 4. Construct bounded evidence package with deterministic correlation
    package_id = f"pkg-{uuid.uuid4().hex[:12]}"
    investigation_id = f"inv-{uuid.uuid4().hex[:12]}"

    # Extract metadata for audit and persistence
    actor_id = getattr(request.state, "user_id", "local_analyst")
    req_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 5. Persist initial 'running' investigation (bounded transaction 1)
    await persistence_service.start_investigation(
        investigation_id=investigation_id,
        alert=alert,
        window_minutes=window_minutes,
        max_items=max_items,
        actor_id=actor_id,
    )

    # 6. Build evidence package
    evidence_package = await evidence_service.build_evidence_package(
        primary_alert=alert,
        package_id=package_id,
        include_related_events=include_related,
        correlation_window_minutes=window_minutes,
        max_related_events=max_related,
        max_evidence_items=max_items,
    )

    # 7. Submit to local Ollama inference with timing and error handling
    start_time = time.monotonic()
    try:
        result = await ollama.investigate_alert(
            package=evidence_package,
            investigation_id=investigation_id,
        )
    except AppException as app_err:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        await persistence_service.fail_investigation(
            investigation_id=investigation_id,
            error_code=app_err.code.value if hasattr(app_err.code, "value") else str(app_err.code),
            error_message=app_err.message,
            duration_ms=duration_ms,
            actor_id=actor_id,
            request_id=req_id,
            client_ip=client_ip,
        )
        raise
    except Exception as exc:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        await persistence_service.fail_investigation(
            investigation_id=investigation_id,
            error_code="INFERENCE_FAILED",
            error_message=str(exc)[:512],
            duration_ms=duration_ms,
            actor_id=actor_id,
            request_id=req_id,
            client_ip=client_ip,
        )
        raise

    duration_ms = int((time.monotonic() - start_time) * 1000)

    # 8. Persist completion atomically (bounded transaction 2)
    try:
        await persistence_service.complete_investigation(
            investigation_id=investigation_id,
            result=result,
            evidence_package=evidence_package,
            duration_ms=duration_ms,
            actor_id=actor_id,
            request_id=req_id,
            client_ip=client_ip,
        )
    except Exception as db_err:
        logger.error(
            "Failed to persist completed investigation %s: %s",
            investigation_id,
            str(db_err),
            exc_info=True,
        )
        try:
            await persistence_service.fail_investigation(
                investigation_id=investigation_id,
                error_code="PERSISTENCE_TRANSACTION_FAILED",
                error_message="Database transaction failed while saving results and evidence snapshots.",
                duration_ms=duration_ms,
                actor_id=actor_id,
                request_id=req_id,
                client_ip=client_ip,
            )
        except Exception:
            pass
        raise AppException(
            code=ErrorCode.INTERNAL_ERROR,
            message="Investigation completed inference but failed to persist results to database.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return result

