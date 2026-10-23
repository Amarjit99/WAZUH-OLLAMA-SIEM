"""Repository for investigation persistence, lifecycle tracking, and evidence snapshots.

Conforms strictly to specs/PHASE_7_DATABASE_SCHEMA.md and specs/PHASE_7_TRD.md.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.investigation import (
    Investigation,
    InvestigationCheck,
    InvestigationEvidenceSnapshot,
    InvestigationFact,
    InvestigationHypothesis,
    InvestigationResult as InvestigationResultModel,
)
from app.schemas.alert import NormalizedAlert
from app.schemas.investigation import EvidencePackage, InvestigationResult

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class InvestigationRepository:
    """Encapsulates all database operations for investigation lifecycle, results, and evidence snapshots."""

    async def get_next_run_sequence(self, session: AsyncSession, alert_id: str) -> int:
        """Query maximum run_sequence for alert_id and return max + 1 (default 1)."""
        stmt = select(func.coalesce(func.max(Investigation.run_sequence), 0)).where(
            Investigation.alert_id == alert_id
        )
        result = await session.execute(stmt)
        max_seq = result.scalar_one()
        return int(max_seq) + 1

    async def get_running_investigation_for_alert(
        self, session: AsyncSession, alert_id: str
    ) -> Optional[Investigation]:
        """Query for an active running investigation for the specified alert_id."""
        stmt = (
            select(Investigation)
            .where(
                Investigation.alert_id == alert_id,
                Investigation.status == "running",
            )
            .order_by(Investigation.created_at.desc())
            .limit(1)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def create_investigation(
        self,
        session: AsyncSession,
        investigation_id: str,
        alert: NormalizedAlert,
        window_minutes: int = 30,
        max_items: int = 10,
        actor_id: str = "local_analyst",
    ) -> Investigation:
        """Create and persist an initial investigation record in 'running' state."""
        target_alert_id = getattr(alert, "alert_id", getattr(alert, "id", str(alert)))
        run_seq = await self.get_next_run_sequence(session, target_alert_id)
        now = utc_now()

        rule_id_val = getattr(alert, "rule_id", None)
        if rule_id_val is None and hasattr(alert, "rule"):
            rule_id_val = getattr(alert.rule, "id", "")

        rule_level_val = getattr(alert, "rule_level", None)
        if rule_level_val is None and hasattr(alert, "rule"):
            rule_level_val = getattr(alert.rule, "level", None)

        agent_name_val = getattr(alert, "agent_name", None)
        if agent_name_val is None and hasattr(alert, "agent"):
            agent_name_val = getattr(alert.agent, "name", None)

        inv = Investigation(
            investigation_id=investigation_id,
            alert_id=target_alert_id,
            run_sequence=run_seq,
            status="running",
            primary_rule_id=str(rule_id_val)[:64] if rule_id_val is not None else "",
            primary_rule_level=rule_level_val,
            primary_agent_name=agent_name_val[:255] if agent_name_val else None,
            query_window_minutes=window_minutes,
            max_evidence_items=max_items,
            actor_id=actor_id[:64],
            created_at=now,
            updated_at=now,
        )
        session.add(inv)
        return inv

    async def record_investigation_success(
        self,
        session: AsyncSession,
        investigation_id: str,
        result: InvestigationResult,
        evidence_package: EvidencePackage,
        duration_ms: int,
    ) -> None:
        """Atomically update investigation to 'completed' and insert result, facts, hypotheses, checks, and snapshots."""
        now = utc_now()
        valid_evidence_ids = {item.evidence_id for item in evidence_package.items}

        # 1. Update investigation status
        stmt = (
            update(Investigation)
            .where(Investigation.investigation_id == investigation_id)
            .values(
                status="completed",
                execution_duration_ms=duration_ms,
                updated_at=now,
            )
        )
        await session.execute(stmt)

        # 2. Insert InvestigationResult
        result_id = str(uuid.uuid4())
        conf_label = (
            result.confidence_label.value
            if hasattr(result.confidence_label, "value")
            else str(result.confidence_label)
        )
        corr_status = (
            result.correlation_status
            if result.correlation_status
            else (
                result.related_events_summary.correlation_status
                if result.related_events_summary
                else "no_related_events_found"
            )
        )

        res_model = InvestigationResultModel(
            result_id=result_id,
            investigation_id=investigation_id,
            model_name=result.model_name[:64],
            model_tag=result.model_tag[:64],
            prompt_version=result.prompt_version[:32],
            summary=result.summary,
            confidence_label=conf_label[:16],
            disclaimer=result.disclaimer,
            limitations_json=json.dumps(result.limitations),
            warnings_json=json.dumps(result.unsupported_citation_warnings),
            correlation_status=corr_status[:32],
            created_at=now,
        )
        session.add(res_model)

        # 3. Insert Facts (validated citations against evidence snapshots)
        for fact in result.observed_facts:
            validated_cites = [cid for cid in fact.cited_evidence_ids if cid in valid_evidence_ids]
            session.add(
                InvestigationFact(
                    fact_id=str(uuid.uuid4()),
                    result_id=result_id,
                    fact_identifier=fact.fact_id[:16],
                    statement=fact.statement,
                    cited_evidence_ids_json=json.dumps(validated_cites),
                )
            )

        # 4. Insert Hypotheses (validated citations against evidence snapshots)
        for hyp in result.hypotheses:
            uncertainty_val = (
                hyp.uncertainty.value
                if hasattr(hyp.uncertainty, "value")
                else str(hyp.uncertainty)
            )
            validated_cites = [cid for cid in hyp.cited_evidence_ids if cid in valid_evidence_ids]
            session.add(
                InvestigationHypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    result_id=result_id,
                    hypothesis_identifier=hyp.hypothesis_id[:16],
                    statement=hyp.statement,
                    uncertainty=uncertainty_val[:16],
                    cited_evidence_ids_json=json.dumps(validated_cites),
                )
            )

        # 5. Insert Recommended Checks (Read-Only)
        for check in result.recommended_checks:
            priority_val = (
                check.priority.value
                if hasattr(check.priority, "value")
                else str(check.priority)
            )
            session.add(
                InvestigationCheck(
                    check_id=str(uuid.uuid4()),
                    result_id=result_id,
                    check_identifier=check.check_id[:16],
                    description=check.description,
                    rationale=check.rationale,
                    priority=priority_val[:16],
                    is_read_only=True,
                )
            )

        # 6. Insert Minimized Evidence Snapshots with safe field bounds
        for item in evidence_package.items:
            session.add(
                InvestigationEvidenceSnapshot(
                    snapshot_id=str(uuid.uuid4()),
                    investigation_id=investigation_id,
                    evidence_id=item.evidence_id[:16],
                    source_record_id=item.source_record_id[:128],
                    event_timestamp=item.event_timestamp,
                    is_primary=item.is_primary,
                    rule_id=item.rule_id[:64],
                    rule_level=item.rule_level,
                    rule_description=item.rule_description[:2048] if item.rule_description else None,
                    agent_name=item.agent_name[:255] if item.agent_name else None,
                    source_ip=item.source_ip[:45] if item.source_ip else None,
                    destination_ip=item.destination_ip[:45] if item.destination_ip else None,
                    username=item.username[:128] if item.username else None,
                    correlation_reason=item.correlation_reason[:64] if item.correlation_reason else None,
                    correlation_qualifier=item.correlation_qualifier[:128] if item.correlation_qualifier else None,
                    raw_evidence_ref=item.raw_evidence_ref[:255],
                )
            )

    async def record_investigation_failure(
        self,
        session: AsyncSession,
        investigation_id: str,
        error_code: str,
        error_message: str,
        duration_ms: Optional[int] = None,
    ) -> None:
        """Update investigation to 'failed' state with error metadata."""
        now = utc_now()
        stmt = (
            update(Investigation)
            .where(Investigation.investigation_id == investigation_id)
            .values(
                status="failed",
                error_code=error_code[:64],
                error_message=error_message[:512],
                execution_duration_ms=duration_ms,
                updated_at=now,
            )
        )
        await session.execute(stmt)

    async def reconcile_orphaned_investigations(
        self, session: AsyncSession
    ) -> List[str]:
        """Mark any investigation left in 'running' state as failed with ORPHANED_PROCESS_CRASH."""
        stmt = select(Investigation.investigation_id).where(
            Investigation.status == "running"
        )
        result = await session.execute(stmt)
        orphaned_ids: List[str] = list(result.scalars().all())

        if not orphaned_ids:
            return []

        now = utc_now()
        update_stmt = (
            update(Investigation)
            .where(Investigation.investigation_id.in_(orphaned_ids))
            .values(
                status="failed",
                error_code="ORPHANED_PROCESS_CRASH",
                error_message="Investigation was in progress when backend process terminated unexpectedly.",
                updated_at=now,
            )
        )
        await session.execute(update_stmt)
        return orphaned_ids

    async def get_investigation_by_id(
        self, session: AsyncSession, investigation_id: str
    ) -> Optional[Investigation]:
        """Retrieve investigation by ID with eager loading of all child relations."""
        stmt = (
            select(Investigation)
            .where(
                Investigation.investigation_id == investigation_id,
                Investigation.deleted_at.is_(None),
            )
            .options(
                selectinload(Investigation.result).selectinload(InvestigationResultModel.facts),
                selectinload(Investigation.result).selectinload(InvestigationResultModel.hypotheses),
                selectinload(Investigation.result).selectinload(InvestigationResultModel.checks),
                selectinload(Investigation.evidence_snapshots),
            )
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_investigations(
        self,
        session: AsyncSession,
        alert_id: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        confidence_label: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 25,
        sort_order: str = "desc",
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query paginated investigation history with safe filtering and deterministic ordering."""
        evidence_count_subq = (
            select(func.count(InvestigationEvidenceSnapshot.snapshot_id))
            .where(InvestigationEvidenceSnapshot.investigation_id == Investigation.investigation_id)
            .scalar_subquery()
        )

        base_stmt = (
            select(
                Investigation,
                InvestigationResultModel.model_name,
                InvestigationResultModel.model_tag,
                InvestigationResultModel.confidence_label,
                InvestigationResultModel.correlation_status,
                evidence_count_subq.label("evidence_count"),
            )
            .outerjoin(
                InvestigationResultModel,
                InvestigationResultModel.investigation_id == Investigation.investigation_id,
            )
            .where(Investigation.deleted_at.is_(None))
        )

        count_stmt = (
            select(func.count(Investigation.investigation_id))
            .where(Investigation.deleted_at.is_(None))
        )

        if alert_id:
            clean_alert = alert_id.strip()
            base_stmt = base_stmt.where(Investigation.alert_id == clean_alert)
            count_stmt = count_stmt.where(Investigation.alert_id == clean_alert)

        if status:
            clean_status = status.strip().lower()
            base_stmt = base_stmt.where(Investigation.status == clean_status)
            count_stmt = count_stmt.where(Investigation.status == clean_status)

        if rule_id:
            clean_rule = rule_id.strip()
            base_stmt = base_stmt.where(Investigation.primary_rule_id == clean_rule)
            count_stmt = count_stmt.where(Investigation.primary_rule_id == clean_rule)

        if agent_name:
            clean_agent = agent_name.strip()
            base_stmt = base_stmt.where(Investigation.primary_agent_name == clean_agent)
            count_stmt = count_stmt.where(Investigation.primary_agent_name == clean_agent)

        if confidence_label:
            clean_conf = confidence_label.strip().lower()
            count_stmt = count_stmt.outerjoin(
                InvestigationResultModel,
                InvestigationResultModel.investigation_id == Investigation.investigation_id,
            )
            base_stmt = base_stmt.where(InvestigationResultModel.confidence_label == clean_conf)
            count_stmt = count_stmt.where(InvestigationResultModel.confidence_label == clean_conf)

        if start_time:
            base_stmt = base_stmt.where(Investigation.created_at >= start_time)
            count_stmt = count_stmt.where(Investigation.created_at >= start_time)

        if end_time:
            base_stmt = base_stmt.where(Investigation.created_at <= end_time)
            count_stmt = count_stmt.where(Investigation.created_at <= end_time)

        total_items = (await session.execute(count_stmt)).scalar_one()

        if sort_order.lower() == "asc":
            order_clauses = [Investigation.created_at.asc(), Investigation.investigation_id.asc()]
        else:
            order_clauses = [Investigation.created_at.desc(), Investigation.investigation_id.desc()]

        clamped_page = max(1, page)
        clamped_size = max(1, min(100, page_size))
        offset = (clamped_page - 1) * clamped_size

        stmt = base_stmt.order_by(*order_clauses).offset(offset).limit(clamped_size)
        rows = (await session.execute(stmt)).all()

        items: List[Dict[str, Any]] = []
        for row in rows:
            inv: Investigation = row[0]
            items.append({
                "investigation_id": inv.investigation_id,
                "alert_id": inv.alert_id,
                "run_sequence": inv.run_sequence,
                "status": inv.status,
                "primary_rule_id": inv.primary_rule_id,
                "primary_rule_level": inv.primary_rule_level,
                "primary_agent_name": inv.primary_agent_name,
                "model_name": row[1],
                "model_tag": row[2],
                "confidence_label": row[3],
                "correlation_status": row[4],
                "evidence_count": row[5] or 0,
                "execution_duration_ms": inv.execution_duration_ms,
                "error_code": inv.error_code,
                "error_message": inv.error_message,
                "created_at": inv.created_at,
                "updated_at": inv.updated_at,
                "actor_id": inv.actor_id,
                "analyst_rating": inv.analyst_rating,
                "analyst_notes": inv.analyst_notes,
                "feedback_submitted_at": inv.feedback_submitted_at,
            })


        return items, int(total_items)

    async def count_expired_investigations(
        self, session: AsyncSession, cutoff: datetime
    ) -> int:
        """Count investigations strictly older than the specified UTC cutoff timestamp."""
        stmt = select(func.count(Investigation.investigation_id)).where(
            Investigation.created_at < cutoff
        )
        return int((await session.execute(stmt)).scalar_one())

    async def get_expired_investigation_ids(
        self, session: AsyncSession, cutoff: datetime, limit: int = 100
    ) -> List[str]:
        """Fetch up to limit investigation IDs strictly older than the cutoff timestamp."""
        stmt = (
            select(Investigation.investigation_id)
            .where(Investigation.created_at < cutoff)
            .order_by(Investigation.created_at.asc(), Investigation.investigation_id.asc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def delete_investigations_by_ids(
        self, session: AsyncSession, investigation_ids: List[str]
    ) -> int:
        """Delete investigations by primary key IDs, relying on database ON DELETE CASCADE for children."""
        if not investigation_ids:
            return 0
        stmt = delete(Investigation).where(Investigation.investigation_id.in_(investigation_ids))
        result = await session.execute(stmt)
        return int(result.rowcount)

    async def submit_feedback(
        self,
        session: AsyncSession,
        investigation_id: str,
        analyst_rating: str,
        analyst_notes: Optional[str] = None,
    ) -> Optional[Investigation]:
        """Record analyst feedback rating and optional notes for an investigation."""
        inv = await self.get_investigation_by_id(session, investigation_id)
        if not inv:
            return None

        now = utc_now()
        inv.analyst_rating = analyst_rating[:32]
        inv.analyst_notes = analyst_notes[:2048] if analyst_notes else None
        inv.feedback_submitted_at = now
        inv.updated_at = now
        await session.flush()
        return inv

