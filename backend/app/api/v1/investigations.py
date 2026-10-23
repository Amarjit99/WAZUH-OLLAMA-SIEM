"""Investigations API router conforming to specs/PHASE_7_API_CONTRACT.md."""

from datetime import datetime, timedelta, timezone
import csv
import io
import json
import logging
import math
from typing import Any, Optional
from fastapi import APIRouter, Depends, Query, Request, Response, status


from app.api.deps import (
    get_investigation_persistence_service,
    verify_api_auth,
)
from app.core.errors import AppException
from app.models.investigation import Investigation
from app.schemas.error import ErrorCode
from app.schemas.investigation import (
    ConfidenceLabel,
    Hypothesis,
    InvestigationStatus,
    ObservedFact,
    PriorityLevel,
    RecommendedCheck,
    UncertaintyLevel,
)
from app.schemas.investigation_history import (
    EvidenceSnapshotItem,
    InvestigationDetailResponse,
    InvestigationDetailResult,
    InvestigationFeedbackRequest,
    InvestigationListResponse,
    InvestigationPagination,
    InvestigationSummaryItem,
)

from app.services.investigation_persistence_service import InvestigationPersistenceService

logger = logging.getLogger("siem.investigations_api")

router = APIRouter(
    prefix="/investigations",
    tags=["Investigations"],
    dependencies=[Depends(verify_api_auth)],
)

VALID_STATUSES = {"queued", "running", "completed", "failed", "cancelled"}
VALID_CONFIDENCES = {"low", "medium", "high", "unverified"}


def _ensure_utc(ts: Optional[datetime], field_name: str) -> Optional[datetime]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


@router.get(
    "",
    response_model=InvestigationListResponse,
    summary="List investigation history",
    description="Query paginated historical investigations with bounded filtering and deterministic ordering.",
)
async def list_investigations_endpoint(
    request: Request,
    alert_id: Optional[str] = Query(None, max_length=128, description="Filter by exact alert ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: queued, running, completed, failed, cancelled"),
    rule_id: Optional[str] = Query(None, max_length=64, description="Filter by primary rule ID"),
    agent_name: Optional[str] = Query(None, max_length=255, description="Filter by agent hostname"),
    confidence_label: Optional[str] = Query(None, description="Filter by confidence label"),
    start_time: Optional[datetime] = Query(None, description="Lower bound for created_at (UTC)"),
    end_time: Optional[datetime] = Query(None, description="Upper bound for created_at (UTC)"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page (max 100)"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order by created_at"),
    persistence_service: InvestigationPersistenceService = Depends(get_investigation_persistence_service),
) -> InvestigationListResponse:
    """List historical investigations with pagination and safe filtering."""
    req_id = getattr(request.state, "request_id", "req-unknown")

    # Validate status enum
    if status_filter:
        clean_status = status_filter.strip().lower()
        if clean_status not in VALID_STATUSES:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message=f"Invalid status filter '{status_filter}'. Allowed: {sorted(VALID_STATUSES)}",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
    else:
        clean_status = None

    # Validate confidence enum
    if confidence_label:
        clean_conf = confidence_label.strip().lower()
        if clean_conf not in VALID_CONFIDENCES:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message=f"Invalid confidence filter '{confidence_label}'. Allowed: {sorted(VALID_CONFIDENCES)}",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
    else:
        clean_conf = None

    # Time window validation
    utc_start = _ensure_utc(start_time, "start_time")
    utc_end = _ensure_utc(end_time, "end_time")
    now_utc = datetime.now(timezone.utc)
    if utc_start and (now_utc - utc_start) > timedelta(days=90, hours=1):
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="start_time cannot be older than the 90 days retention window",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    if utc_start and utc_end:
        if utc_start > utc_end:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="start_time must be earlier than or equal to end_time",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if (utc_end - utc_start) > timedelta(days=90):
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="Query window cannot exceed 90 days limit",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    items_raw, total_count = await persistence_service.list_investigations(
        alert_id=alert_id,
        status=clean_status,
        rule_id=rule_id,
        agent_name=agent_name,
        confidence_label=clean_conf,
        start_time=utc_start,
        end_time=utc_end,
        page=page,
        page_size=page_size,
        sort_order=sort_order,
    )

    items = [InvestigationSummaryItem(**item) for item in items_raw]
    total_pages = math.ceil(total_count / page_size) if total_count > 0 else 0
    has_next = page < total_pages
    has_prev = page > 1

    pagination = InvestigationPagination(
        page=page,
        page_size=page_size,
        total_items=total_count,
        total_pages=total_pages,
        has_next=has_next,
        has_prev=has_prev,
    )

    return InvestigationListResponse(
        items=items,
        pagination=pagination,
        request_id=req_id,
    )


@router.get(
    "/{investigation_id}",
    response_model=InvestigationDetailResponse,
    summary="Retrieve investigation detail",
    description="Retrieve full persisted results, facts, hypotheses, checks, and evidence snapshots for an investigation.",
)
async def get_investigation_detail_endpoint(
    investigation_id: str,
    request: Request,
    persistence_service: InvestigationPersistenceService = Depends(get_investigation_persistence_service),
) -> InvestigationDetailResponse:
    """Retrieve complete persisted investigation details including child evidence snapshots."""
    clean_id = investigation_id.strip()
    if not clean_id or len(clean_id) > 64:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="Invalid investigation ID format",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    actor_id = getattr(request.state, "user_id", "local_analyst")
    req_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    inv = await persistence_service.get_investigation_detail(
        investigation_id=clean_id,
        actor_id=actor_id,
        request_id=req_id,
        client_ip=client_ip,
    )

    if inv is None:
        raise AppException(
            code=ErrorCode.NOT_FOUND,
            message=f"Investigation with ID '{clean_id}' was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Map AI result if present
    result_detail = None
    if inv.result is not None:
        res = inv.result

        facts = []
        for f in res.facts:
            try:
                cites = json.loads(f.cited_evidence_ids_json)
            except Exception:
                cites = []
            facts.append(
                ObservedFact(
                    fact_id=f.fact_identifier,
                    statement=f.statement,
                    cited_evidence_ids=cites,
                )
            )

        hypotheses = []
        for h in res.hypotheses:
            try:
                cites = json.loads(h.cited_evidence_ids_json)
            except Exception:
                cites = []
            hypotheses.append(
                Hypothesis(
                    hypothesis_id=h.hypothesis_identifier,
                    statement=h.statement,
                    uncertainty=UncertaintyLevel(h.uncertainty.lower()) if h.uncertainty.lower() in ("low", "medium", "high") else UncertaintyLevel.MEDIUM,
                    cited_evidence_ids=cites,
                )
            )

        checks = []
        for c in res.checks:
            checks.append(
                RecommendedCheck(
                    check_id=c.check_identifier,
                    description=c.description,
                    rationale=c.rationale or "",
                    priority=PriorityLevel(c.priority.lower()) if c.priority.lower() in ("low", "medium", "high") else PriorityLevel.MEDIUM,
                    is_read_only=True,
                )
            )

        try:
            limitations = json.loads(res.limitations_json)
        except Exception:
            limitations = []

        try:
            warnings = json.loads(res.warnings_json)
        except Exception:
            warnings = []

        result_detail = InvestigationDetailResult(
            model_name=res.model_name,
            model_tag=res.model_tag,
            prompt_version=res.prompt_version,
            summary=res.summary,
            confidence_label=res.confidence_label,
            disclaimer=res.disclaimer,
            observed_facts=facts,
            hypotheses=hypotheses,
            recommended_checks=checks,
            limitations=limitations,
            unsupported_citation_warnings=warnings,
            correlation_status=res.correlation_status,
        )

    # Map evidence snapshots (ordered: primary first, then by evidence_id)
    sorted_snapshots = sorted(
        inv.evidence_snapshots,
        key=lambda s: (not s.is_primary, s.evidence_id),
    )
    evidence_items = [
        EvidenceSnapshotItem(
            evidence_id=s.evidence_id,
            source_record_id=s.source_record_id,
            event_timestamp=s.event_timestamp,
            is_primary=s.is_primary,
            rule_id=s.rule_id,
            rule_level=s.rule_level,
            rule_description=s.rule_description,
            agent_name=s.agent_name,
            source_ip=s.source_ip,
            destination_ip=s.destination_ip,
            username=s.username,
            correlation_reason=s.correlation_reason,
            correlation_qualifier=s.correlation_qualifier,
            raw_evidence_ref=s.raw_evidence_ref,
        )
        for s in sorted_snapshots
    ]

    return InvestigationDetailResponse(
        investigation_id=inv.investigation_id,
        alert_id=inv.alert_id,
        run_sequence=inv.run_sequence,
        status=inv.status,
        primary_rule_id=inv.primary_rule_id,
        primary_rule_level=inv.primary_rule_level,
        primary_agent_name=inv.primary_agent_name,
        query_window_minutes=inv.query_window_minutes,
        max_evidence_items=inv.max_evidence_items,
        error_code=inv.error_code,
        error_message=inv.error_message,
        execution_duration_ms=inv.execution_duration_ms,
        created_at=inv.created_at,
        updated_at=inv.updated_at,
        actor_id=inv.actor_id,
        analyst_rating=inv.analyst_rating,
        analyst_notes=inv.analyst_notes,
        feedback_submitted_at=inv.feedback_submitted_at,
        result=result_detail,
        evidence_items=evidence_items,
        request_id=req_id,
    )


@router.post(
    "/{investigation_id}/feedback",
    response_model=InvestigationDetailResponse,
    summary="Submit analyst feedback rating for an investigation",
    description="Submit an evaluation rating ('helpful', 'incorrect', 'incomplete') and optional notes.",
)
async def submit_investigation_feedback_endpoint(
    investigation_id: str,
    payload: InvestigationFeedbackRequest,
    request: Request,
    persistence_service: InvestigationPersistenceService = Depends(get_investigation_persistence_service),
) -> InvestigationDetailResponse:
    """Submit analyst feedback rating and commentary on an AI investigation."""
    clean_id = investigation_id.strip()
    clean_rating = payload.rating.strip().lower()
    if clean_rating not in {"helpful", "incorrect", "incomplete"}:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="Rating must be one of: 'helpful', 'incorrect', 'incomplete'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    actor_id = getattr(request.state, "user_id", "local_analyst")
    req_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    inv = await persistence_service.record_feedback(
        investigation_id=clean_id,
        rating=clean_rating,
        notes=payload.notes.strip() if payload.notes else None,
        actor_id=actor_id,
        request_id=req_id,
        client_ip=client_ip,
    )
    if inv is None:
        raise AppException(
            code=ErrorCode.NOT_FOUND,
            message=f"Investigation with ID '{clean_id}' was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    return await get_investigation_detail_endpoint(
        investigation_id=clean_id,
        request=request,
        persistence_service=persistence_service,
    )


from app.core.sanitization import sanitize_csv_formula

_sanitize_formula = sanitize_csv_formula


@router.get(
    "/{investigation_id}/export",
    summary="Export investigation report",
    description="Export a sanitized markdown, CSV, or JSON forensic report for offline review.",
)
async def export_investigation_endpoint(
    investigation_id: str,
    request: Request,
    format: str = Query(default="markdown", pattern="^(markdown|json|csv)$"),
    persistence_service: InvestigationPersistenceService = Depends(get_investigation_persistence_service),
) -> Response:
    """Export investigation findings as sanitized markdown, CSV, or structured JSON."""
    clean_id = investigation_id.strip()
    detail = await get_investigation_detail_endpoint(
        investigation_id=clean_id,
        request=request,
        persistence_service=persistence_service,
    )

    actor_id = getattr(request.state, "user_id", "local_analyst")
    req_id = getattr(request.state, "request_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Audit the export event
    async with persistence_service.session_factory() as session:
        async with session.begin():
            await persistence_service.audit_repo.log_event(
                session=session,
                actor_id=actor_id,
                action="INVESTIGATION_EXPORTED",
                resource_type="investigation",
                resource_id=clean_id,
                outcome="SUCCESS",
                request_id=req_id,
                client_ip=client_ip,
                metadata={"format": format, "alert_id": detail.alert_id},
            )

    if format == "json":
        export_dict = {
            "investigation_id": _sanitize_formula(detail.investigation_id),
            "alert_id": _sanitize_formula(detail.alert_id),
            "run_sequence": detail.run_sequence,
            "status": _sanitize_formula(detail.status),
            "primary_rule_id": _sanitize_formula(detail.primary_rule_id),
            "primary_rule_level": detail.primary_rule_level,
            "primary_agent_name": _sanitize_formula(detail.primary_agent_name),
            "created_at": detail.created_at.isoformat(),
            "updated_at": detail.updated_at.isoformat(),
            "actor_id": _sanitize_formula(detail.actor_id),
            "analyst_rating": _sanitize_formula(detail.analyst_rating),
            "analyst_notes": _sanitize_formula(detail.analyst_notes),
            "feedback_submitted_at": detail.feedback_submitted_at.isoformat() if detail.feedback_submitted_at else None,
            "result": detail.result.model_dump() if detail.result else None,
            "evidence_items": [e.model_dump() for e in detail.evidence_items],
            "disclaimer": "Authoritative detector of record: Wazuh. AI recommendations are read-only advisory guidance.",
        }
        json_content = json.dumps(export_dict, indent=2, default=str)
        return Response(
            content=json_content,
            media_type="application/json; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="investigation_{clean_id}.json"'
            },
        )

    if format == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            "Investigation ID",
            "Evidence ID",
            "Role",
            "Timestamp UTC",
            "Rule ID",
            "Rule Level",
            "Rule Description",
            "Agent Name",
            "Source IP",
            "Destination IP",
            "Username",
            "Correlation Signal",
            "Correlation Qualifier",
            "Raw Ref",
        ])
        for ev in detail.evidence_items:
            writer.writerow([
                _sanitize_formula(detail.investigation_id),
                _sanitize_formula(ev.evidence_id),
                "PRIMARY" if ev.is_primary else "RELATED",
                ev.event_timestamp.isoformat() if ev.event_timestamp else "",
                _sanitize_formula(ev.rule_id),
                ev.rule_level if ev.rule_level is not None else "",
                _sanitize_formula(ev.rule_description or ""),
                _sanitize_formula(ev.agent_name or ""),
                _sanitize_formula(ev.source_ip or ""),
                _sanitize_formula(ev.destination_ip or ""),
                _sanitize_formula(ev.username or ""),
                _sanitize_formula(ev.correlation_reason or ""),
                _sanitize_formula(ev.correlation_qualifier or ""),
                _sanitize_formula(ev.raw_evidence_ref or ""),
            ])
        csv_content = out.getvalue()
        return Response(
            content=csv_content,
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="investigation_{clean_id}.csv"'
            },
        )

    # Markdown export
    lines = []
    lines.append(f"# Forensic Investigation Report: {_sanitize_formula(detail.investigation_id)}")
    lines.append("")
    lines.append("## Overview")
    lines.append(f"- **Alert ID**: {_sanitize_formula(detail.alert_id)}")
    lines.append(f"- **Status**: {_sanitize_formula(detail.status)}")
    lines.append(f"- **Primary Rule**: {_sanitize_formula(detail.primary_rule_id)} (Level {detail.primary_rule_level})")
    primary_ev = next((e for e in detail.evidence_items if e.is_primary), None)
    if primary_ev and primary_ev.rule_description:
        lines.append(f"- **Rule Description**: {_sanitize_formula(primary_ev.rule_description)}")
    lines.append(f"- **Agent**: {_sanitize_formula(detail.primary_agent_name or 'N/A')}")
    lines.append(f"- **Execution Time**: {detail.created_at.isoformat()}")
    if detail.analyst_rating:
        lines.append(f"- **Analyst Evaluation**: {_sanitize_formula(detail.analyst_rating.upper())}")
    if detail.analyst_notes:
        lines.append(f"- **Analyst Notes**: {_sanitize_formula(detail.analyst_notes)}")
    lines.append("")

    if detail.result:
        res = detail.result
        lines.append("## AI Findings Summary")
        lines.append(f"- **Model**: {_sanitize_formula(res.model_name)} ({_sanitize_formula(res.model_tag)})")
        lines.append(f"- **Confidence**: {_sanitize_formula(res.confidence_label.upper())}")
        lines.append(f"- **Correlation Outcome**: {_sanitize_formula(res.correlation_status)}")
        lines.append("")
        lines.append("### Executive Summary")
        lines.append(_sanitize_formula(res.summary))
        lines.append("")

        if res.observed_facts:
            lines.append("### Observed Facts")
            for fact in res.observed_facts:
                cites = f" (Citations: {', '.join(fact.cited_evidence_ids)})" if fact.cited_evidence_ids else ""
                lines.append(f"- **[{_sanitize_formula(fact.fact_id)}]** {_sanitize_formula(fact.statement)}{cites}")
            lines.append("")

        if res.hypotheses:
            lines.append("### Hypotheses & Uncertainty")
            for hyp in res.hypotheses:
                unc = hyp.uncertainty.value if hasattr(hyp.uncertainty, "value") else str(hyp.uncertainty)
                cites = f" (Citations: {', '.join(hyp.cited_evidence_ids)})" if hyp.cited_evidence_ids else ""
                lines.append(f"- **[{_sanitize_formula(hyp.hypothesis_id)}]** {_sanitize_formula(hyp.statement)} *(Uncertainty: {unc.upper()})*{cites}")
            lines.append("")

        if res.recommended_checks:
            lines.append("### Defensive Recommended Checks (Read-Only)")
            for check in res.recommended_checks:
                pri = check.priority.value if hasattr(check.priority, "value") else str(check.priority)
                lines.append(f"- **[{_sanitize_formula(check.check_id)}]** [Priority: {pri.upper()}] {_sanitize_formula(check.description)}")
                if check.rationale:
                    lines.append(f"  - *Rationale*: {_sanitize_formula(check.rationale)}")
            lines.append("")

    if detail.evidence_items:
        lines.append("## Evaluated Evidence Snapshots")
        lines.append("| Evidence ID | Type | Timestamp | Rule ID | Description | Agent | Source IP | Destination IP |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for ev in detail.evidence_items:
            ev_type = "Primary Alert" if ev.is_primary else "Correlated Event"
            ts = ev.event_timestamp.isoformat() if ev.event_timestamp else ""
            lines.append(
                f"| {_sanitize_formula(ev.evidence_id)} | {ev_type} | {ts} | "
                f"{_sanitize_formula(ev.rule_id)} | {_sanitize_formula(ev.rule_description or '-')} | "
                f"{_sanitize_formula(ev.agent_name or '-')} | "
                f"{_sanitize_formula(ev.source_ip or '-')} | {_sanitize_formula(ev.destination_ip or '-')} |"
            )
        lines.append("")

    lines.append("---")
    lines.append("**Disclaimer:** Authoritative detection and alerting system is Wazuh. AI recommendations are strictly advisory and read-only.")
    lines.append("")

    md_content = "\n".join(lines)
    return Response(
        content=md_content,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="investigation_{clean_id}.md"'
        },
    )


