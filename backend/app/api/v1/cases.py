import csv
from datetime import datetime, timezone
import io
import json
import logging
import math
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.core.sanitization import sanitize_csv_formula

from app.api.deps import (
    get_case_repository,
    verify_api_auth,
)
from app.core.errors import AppException
from app.db.session import get_session_factory
from app.repositories.audit_repository import AuditRepository
from app.repositories.case_repository import CaseRepository
from app.schemas.case import (
    CaseCreate,
    CaseListResponse,
    CasePagination,
    CaseResponse,
    CaseUpdate,
)
from app.schemas.error import ErrorCode

logger = logging.getLogger("siem.cases_api")

router = APIRouter(
    prefix="/cases",
    tags=["Cases"],
    dependencies=[Depends(verify_api_auth)],
)

VALID_STATUSES = {"open", "in_progress", "resolved", "closed"}
VALID_PRIORITIES = {"low", "medium", "high", "critical"}


def _ensure_utc(ts: Optional[datetime]) -> Optional[datetime]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List cases",
    description="Query paginated active cases with status/priority filtering and deterministic ordering.",
)
async def list_cases_endpoint(
    request: Request,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by case status"),
    priority: Optional[str] = Query(None, description="Filter by case priority"),
    assignee: Optional[str] = Query(None, description="Filter by assignee substring"),
    alert_id: Optional[str] = Query(None, description="Filter by associated alert ID"),
    start_time: Optional[datetime] = Query(None, description="Filter by created_at >= start_time"),
    end_time: Optional[datetime] = Query(None, description="Filter by created_at <= end_time"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order by created_at"),
    case_repo: CaseRepository = Depends(get_case_repository),
) -> CaseListResponse:
    req_id = getattr(request.state, "request_id", "req-unknown")

    if status_filter and status_filter.lower() not in VALID_STATUSES:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid status '{status_filter}'. Must be one of: {sorted(VALID_STATUSES)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if priority and priority.lower() not in VALID_PRIORITIES:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid priority '{priority}'. Must be one of: {sorted(VALID_PRIORITIES)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    utc_start = _ensure_utc(start_time)
    utc_end = _ensure_utc(end_time)

    session_factory = get_session_factory()
    async with session_factory() as session:
        cases, total_items = await case_repo.list_cases(
            session=session,
            status=status_filter,
            priority=priority,
            assignee=assignee,
            alert_id=alert_id,
            start_time=utc_start,
            end_time=utc_end,
            page=page,
            page_size=page_size,
            sort_order=sort_order,
        )

    total_pages = math.ceil(total_items / page_size) if total_items > 0 else 0
    pagination = CasePagination(
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
        has_next=(page < total_pages),
        has_prev=(page > 1 and total_pages > 0),
    )

    items = [CaseResponse.model_validate(c) for c in cases]
    return CaseListResponse(
        items=items,
        pagination=pagination,
        request_id=req_id,
    )


@router.post(
    "",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new case",
    description="Create a new incident investigation case linking optional alerts and investigations.",
)
async def create_case_endpoint(
    payload: CaseCreate,
    request: Request,
    case_repo: CaseRepository = Depends(get_case_repository),
) -> CaseResponse:
    actor_id = getattr(request.state, "user_id", "local_analyst")
    req_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    if payload.priority.lower() not in VALID_PRIORITIES:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid priority. Must be one of: {sorted(VALID_PRIORITIES)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_factory = get_session_factory()
    audit_repo = AuditRepository()

    async with session_factory() as session:
        async with session.begin():
            case = await case_repo.create_case(
                session=session,
                title=payload.title,
                description=payload.description,
                priority=payload.priority,
                assignee=payload.assignee,
                alert_id=payload.alert_id,
                investigation_id=payload.investigation_id,
                analyst_notes=payload.analyst_notes,
            )
            await audit_repo.log_event(
                session=session,
                actor_id=actor_id,
                action="CASE_CREATED",
                resource_type="case",
                resource_id=case.case_id,
                outcome="SUCCESS",
                request_id=req_id,
                client_ip=client_ip,
                metadata={
                    "title": case.title,
                    "priority": case.priority,
                    "alert_id": case.alert_id,
                    "investigation_id": case.investigation_id,
                },
            )

        resp = CaseResponse.model_validate(case)
        return resp


@router.get(
    "/export",
    summary="Export cases",
    description="Export filtered investigation cases as sanitized CSV or JSON with formula injection protection and audit logging.",
)
async def export_cases(
    request: Request,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    status: Optional[str] = Query(None, description="Filter by case status"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    assignee: Optional[str] = Query(None, description="Filter by assignee substring"),
    alert_id: Optional[str] = Query(None, description="Filter by alert ID"),
    limit: int = Query(500, ge=1, le=1000, description="Maximum cases to export"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order by created_at"),
    case_repo: CaseRepository = Depends(get_case_repository),
) -> Response:
    """Export filtered cases as sanitized CSV or JSON with audit logging."""
    clean_status = status.strip().lower() if status else None
    if clean_status and clean_status not in VALID_STATUSES:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid status '{status}'. Must be one of: {sorted(VALID_STATUSES)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    clean_priority = priority.strip().lower() if priority else None
    if clean_priority and clean_priority not in VALID_PRIORITIES:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid priority '{priority}'. Must be one of: {sorted(VALID_PRIORITIES)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    actor_id = getattr(request.state, "user_id", "local_analyst")
    req_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    session_factory = get_session_factory()
    audit_repo = AuditRepository()

    async with session_factory() as session:
        async with session.begin():
            cases, total_count = await case_repo.list_cases(
                session=session,
                status=clean_status,
                priority=clean_priority,
                assignee=assignee,
                alert_id=alert_id,
                page=1,
                page_size=limit,
                sort_order=sort_order,
            )

            await audit_repo.log_event(
                session=session,
                actor_id=actor_id,
                action="CASES_EXPORTED",
                resource_type="cases",
                resource_id="collection",
                outcome="SUCCESS",
                request_id=req_id,
                client_ip=client_ip,
                metadata={
                    "format": format,
                    "count": len(cases),
                    "total_available": total_count,
                    "status_filter": clean_status,
                    "priority_filter": clean_priority,
                },
            )

    if format == "json":
        export_dict = [CaseResponse.model_validate(c).model_dump() for c in cases]
        json_content = json.dumps(export_dict, indent=2, default=str)
        return Response(
            content=json_content,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="cases_export.json"'},
        )

    # format == "csv"
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "Case ID",
        "Title",
        "Status",
        "Priority",
        "Assignee",
        "Created At UTC",
        "Updated At UTC",
        "Alert ID",
        "Investigation ID",
        "Description",
        "Analyst Notes",
    ])
    for c in cases:
        writer.writerow([
            sanitize_csv_formula(c.case_id),
            sanitize_csv_formula(c.title),
            sanitize_csv_formula(c.status),
            sanitize_csv_formula(c.priority),
            sanitize_csv_formula(c.assignee or ""),
            c.created_at.isoformat() if c.created_at else "",
            c.updated_at.isoformat() if c.updated_at else "",
            sanitize_csv_formula(c.alert_id or ""),
            sanitize_csv_formula(c.investigation_id or ""),
            sanitize_csv_formula(c.description or ""),
            sanitize_csv_formula(c.analyst_notes or ""),
        ])

    return Response(
        content=out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="cases_export.csv"'},
    )


@router.get(
    "/{case_id}",
    response_model=CaseResponse,
    summary="Get case details",
    description="Retrieve full details for an active case.",
)
async def get_case_endpoint(
    case_id: str,
    request: Request,
    case_repo: CaseRepository = Depends(get_case_repository),
) -> CaseResponse:
    clean_id = case_id.strip()
    session_factory = get_session_factory()
    async with session_factory() as session:
        case = await case_repo.get_case_by_id(session, clean_id)
        if not case:
            raise AppException(
                code=ErrorCode.NOT_FOUND,
                message=f"Case with ID '{clean_id}' was not found",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return CaseResponse.model_validate(case)


@router.patch(
    "/{case_id}",
    response_model=CaseResponse,
    summary="Update case",
    description="Update status, priority, assignee, title, description, or analyst notes on a case.",
)
async def update_case_endpoint(
    case_id: str,
    payload: CaseUpdate,
    request: Request,
    case_repo: CaseRepository = Depends(get_case_repository),
) -> CaseResponse:
    clean_id = case_id.strip()
    actor_id = getattr(request.state, "user_id", "local_analyst")
    req_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    if payload.status and payload.status.lower() not in VALID_STATUSES:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid status '{payload.status}'. Must be one of: {sorted(VALID_STATUSES)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if payload.priority and payload.priority.lower() not in VALID_PRIORITIES:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message=f"Invalid priority '{payload.priority}'. Must be one of: {sorted(VALID_PRIORITIES)}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_factory = get_session_factory()
    audit_repo = AuditRepository()

    async with session_factory() as session:
        async with session.begin():
            case = await case_repo.update_case(
                session=session,
                case_id=clean_id,
                title=payload.title,
                description=payload.description,
                status=payload.status,
                priority=payload.priority,
                assignee=payload.assignee,
                analyst_notes=payload.analyst_notes,
            )
            if not case:
                raise AppException(
                    code=ErrorCode.NOT_FOUND,
                    message=f"Case with ID '{clean_id}' was not found",
                    status_code=status.HTTP_404_NOT_FOUND,
                )

            await audit_repo.log_event(
                session=session,
                actor_id=actor_id,
                action="CASE_UPDATED",
                resource_type="case",
                resource_id=case.case_id,
                outcome="SUCCESS",
                request_id=req_id,
                client_ip=client_ip,
                metadata={
                    "updated_status": payload.status,
                    "updated_priority": payload.priority,
                    "updated_assignee": payload.assignee,
                },
            )

        return CaseResponse.model_validate(case)


@router.delete(
    "/{case_id}",
    summary="Delete case",
    description="Soft-delete a case from active view.",
)
async def delete_case_endpoint(
    case_id: str,
    request: Request,
    case_repo: CaseRepository = Depends(get_case_repository),
) -> dict:
    clean_id = case_id.strip()
    actor_id = getattr(request.state, "user_id", "local_analyst")
    req_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    session_factory = get_session_factory()
    audit_repo = AuditRepository()

    async with session_factory() as session:
        async with session.begin():
            success = await case_repo.delete_case(session, clean_id)
            if not success:
                raise AppException(
                    code=ErrorCode.NOT_FOUND,
                    message=f"Case with ID '{clean_id}' was not found",
                    status_code=status.HTTP_404_NOT_FOUND,
                )

            await audit_repo.log_event(
                session=session,
                actor_id=actor_id,
                action="CASE_DELETED",
                resource_type="case",
                resource_id=clean_id,
                outcome="SUCCESS",
                request_id=req_id,
                client_ip=client_ip,
                metadata={"case_id": clean_id},
            )

    return {"message": "Case deleted successfully", "case_id": clean_id}
