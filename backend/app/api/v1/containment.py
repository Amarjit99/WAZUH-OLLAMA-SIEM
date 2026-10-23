"""Analyst-Approved Containment and Active Response API Endpoints."""

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_containment_service, verify_api_auth
from app.db.session import get_session_factory
from app.models.audit import AuditEvent
from app.schemas.containment import (
    ContainmentExecutionRequest,
    ContainmentExecutionResponse,
    ContainmentProposalRequest,
    ContainmentProposalResponse,
)
from app.services.containment_service import ContainmentService

logger = logging.getLogger("siem.api.containment")
router = APIRouter(prefix="/containment", tags=["Containment"])


@router.post(
    "/propose",
    response_model=ContainmentProposalResponse,
    summary="Generate containment recommendations",
    description="Analyzes security event context and returns platform-tailored mitigation commands for analyst review.",
)
async def propose_containment_actions(
    request: ContainmentProposalRequest,
    containment_service: ContainmentService = Depends(get_containment_service),
    _authorized: bool = Depends(verify_api_auth),
) -> ContainmentProposalResponse:
    """Propose containment playbooks without executing anything."""
    return containment_service.propose_containment(request)


@router.post(
    "/execute",
    response_model=ContainmentExecutionResponse,
    summary="Authorize and log containment action",
    description="Explicit human-in-the-loop authorization gate. Generates final commands and commits to SHA-256 tamper-evident audit log.",
)
async def execute_containment_action(
    req_body: ContainmentExecutionRequest,
    request: Request,
    containment_service: ContainmentService = Depends(get_containment_service),
    _authorized: bool = Depends(verify_api_auth),
) -> ContainmentExecutionResponse:
    """Authorize a containment playbook with strict human confirmation."""
    request_id = getattr(request.state, "correlation_id", "req-unknown")
    client_ip = request.client.host if request.client else "127.0.0.1"

    session_factory = get_session_factory()
    async with session_factory() as session:
        return await containment_service.approve_and_log_containment(
            request=req_body,
            session=session,
            request_id=request_id,
            client_ip=client_ip,
        )


@router.get(
    "/history",
    summary="List audited containment actions",
    description="Query chronological log of all authorized containment events from tamper-evident audit trail.",
)
async def get_containment_history(
    limit: int = 20,
    _authorized: bool = Depends(verify_api_auth),
) -> List[Dict[str, Any]]:
    """Retrieve recent audited containment records."""
    clamped_limit = min(max(1, limit), 100)
    session_factory = get_session_factory()
    async with session_factory() as session:
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.resource_type == "CONTAINMENT")
            .order_by(AuditEvent.timestamp.desc())
            .limit(clamped_limit)
        )
        res = await session.execute(stmt)
        events = res.scalars().all()

        records = []
        for e in events:
            meta = {}
            if e.metadata_json:
                try:
                    meta = json.loads(e.metadata_json)
                except Exception:
                    pass

            records.append(
                {
                    "audit_id": e.audit_id,
                    "timestamp": e.timestamp.isoformat(),
                    "actor_id": e.actor_id,
                    "action": e.action,
                    "resource_id": e.resource_id,
                    "outcome": e.outcome,
                    "event_hash": e.event_hash,
                    "target": meta.get("target"),
                    "action_type": meta.get("action_type"),
                    "rationale": meta.get("rationale"),
                    "alert_id": meta.get("alert_id"),
                }
            )
        return records
