"""Service coordinating investigation lifecycle persistence, snapshots, and audit logging.

Conforms strictly to specs/PHASE_7_DATABASE_SCHEMA.md, specs/PHASE_7_TRD.md, and specs/PHASE_7_SECURITY_AND_RETENTION.md.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.session import get_session_factory
from app.models.investigation import Investigation
from app.repositories.audit_repository import AuditRepository
from app.repositories.investigation_repository import InvestigationRepository
from app.schemas.alert import NormalizedAlert
from app.schemas.investigation import EvidencePackage, InvestigationResult

logger = logging.getLogger("siem.persistence")


class InvestigationPersistenceService:
    """Manages transactional boundaries and audit logging for investigation lifecycle operations."""

    def __init__(
        self,
        session_factory: Optional[async_sessionmaker[AsyncSession]] = None,
        investigation_repo: Optional[InvestigationRepository] = None,
        audit_repo: Optional[AuditRepository] = None,
    ):
        self._session_factory = session_factory
        self.investigation_repo = investigation_repo or InvestigationRepository()
        self.audit_repo = audit_repo or AuditRepository()

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        if self._session_factory is None:
            self._session_factory = get_session_factory()
        return self._session_factory

    async def get_running_investigation_for_alert(self, alert_id: str) -> Optional[Investigation]:
        """Query if an investigation is currently active ('running') for this alert."""
        async with self.session_factory() as session:
            return await self.investigation_repo.get_running_investigation_for_alert(session, alert_id)

    async def get_investigation_by_id(self, investigation_id: str) -> Optional[Investigation]:
        """Retrieve full investigation by ID including result, child facts, hypotheses, and snapshots."""
        async with self.session_factory() as session:
            return await self.investigation_repo.get_investigation_by_id(session, investigation_id)

    async def list_investigations(
        self,
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
        """Retrieve paginated investigation summaries with filters."""
        async with self.session_factory() as session:
            return await self.investigation_repo.list_investigations(
                session=session,
                alert_id=alert_id,
                status=status,
                rule_id=rule_id,
                agent_name=agent_name,
                confidence_label=confidence_label,
                start_time=start_time,
                end_time=end_time,
                page=page,
                page_size=page_size,
                sort_order=sort_order,
            )

    async def get_investigation_detail(
        self,
        investigation_id: str,
        actor_id: str = "local_analyst",
        request_id: str = "req-unknown",
        client_ip: str = "127.0.0.1",
    ) -> Optional[Investigation]:
        """Retrieve full investigation detail and log INVESTIGATION_VIEWED audit event."""
        async with self.session_factory() as session:
            async with session.begin():
                inv = await self.investigation_repo.get_investigation_by_id(session, investigation_id)
                if inv is None:
                    return None

                await self.audit_repo.log_event(
                    session=session,
                    actor_id=actor_id,
                    action="INVESTIGATION_VIEWED",
                    resource_type="investigation",
                    resource_id=investigation_id,
                    outcome="SUCCESS",
                    request_id=request_id,
                    client_ip=client_ip,
                    metadata={
                        "alert_id": inv.alert_id,
                        "status": inv.status,
                        "run_sequence": inv.run_sequence,
                    },
                )
                return inv

    async def start_investigation(
        self,
        investigation_id: str,
        alert: NormalizedAlert,
        window_minutes: int = 30,
        max_items: int = 10,
        actor_id: str = "local_analyst",
    ) -> Investigation:
        """Atomically record the initiation of an investigation before invoking inference."""
        async with self.session_factory() as session:
            async with session.begin():
                inv = await self.investigation_repo.create_investigation(
                    session=session,
                    investigation_id=investigation_id,
                    alert=alert,
                    window_minutes=window_minutes,
                    max_items=max_items,
                    actor_id=actor_id,
                )
                target_id = getattr(alert, "alert_id", getattr(alert, "id", str(alert)))
                logger.debug(
                    "Persisted initial 'running' investigation %s for alert %s (run sequence %d)",
                    investigation_id,
                    target_id,
                    inv.run_sequence,
                )
                return inv

    async def complete_investigation(
        self,
        investigation_id: str,
        result: InvestigationResult,
        evidence_package: EvidencePackage,
        duration_ms: int,
        actor_id: str = "local_analyst",
        request_id: str = "req-unknown",
        client_ip: str = "127.0.0.1",
    ) -> None:
        """Atomically persist synthesis results, facts, hypotheses, checks, snapshots, and audit log."""
        conf_label = (
            result.confidence_label.value
            if hasattr(result.confidence_label, "value")
            else str(result.confidence_label)
        )
        async with self.session_factory() as session:
            async with session.begin():
                await self.investigation_repo.record_investigation_success(
                    session=session,
                    investigation_id=investigation_id,
                    result=result,
                    evidence_package=evidence_package,
                    duration_ms=duration_ms,
                )
                await self.audit_repo.log_event(
                    session=session,
                    actor_id=actor_id,
                    action="INVESTIGATION_COMPLETED",
                    resource_type="investigation",
                    resource_id=investigation_id,
                    outcome="SUCCESS",
                    request_id=request_id,
                    client_ip=client_ip,
                    metadata={
                        "alert_id": result.alert_id,
                        "confidence": conf_label,
                        "duration_ms": duration_ms,
                        "evidence_count": len(evidence_package.items),
                        "model": f"{result.model_name}:{result.model_tag}",
                    },
                )
        logger.info(
            "Persisted completed investigation %s in %d ms (confidence: %s, %d evidence items)",
            investigation_id,
            duration_ms,
            conf_label,
            len(evidence_package.items),
        )

    async def fail_investigation(
        self,
        investigation_id: str,
        error_code: str,
        error_message: str,
        duration_ms: Optional[int] = None,
        actor_id: str = "local_analyst",
        request_id: str = "req-unknown",
        client_ip: str = "127.0.0.1",
    ) -> None:
        """Atomically record an investigation failure and write corresponding audit event."""
        async with self.session_factory() as session:
            async with session.begin():
                await self.investigation_repo.record_investigation_failure(
                    session=session,
                    investigation_id=investigation_id,
                    error_code=error_code,
                    error_message=error_message,
                    duration_ms=duration_ms,
                )
                await self.audit_repo.log_event(
                    session=session,
                    actor_id=actor_id,
                    action="INVESTIGATION_FAILED",
                    resource_type="investigation",
                    resource_id=investigation_id,
                    outcome="FAILURE",
                    request_id=request_id,
                    client_ip=client_ip,
                    metadata={
                        "error_code": error_code,
                        "error_message": error_message[:256],
                        "duration_ms": duration_ms,
                    },
                )
        logger.warning(
            "Recorded failed investigation %s (error_code: %s, message: %s)",
            investigation_id,
            error_code,
            error_message[:128],
        )

    async def reconcile_orphaned_at_startup(self) -> int:
        """Reconcile orphaned investigations stranded in 'running' state from previous process crashes."""
        async with self.session_factory() as session:
            async with session.begin():
                orphaned_ids = await self.investigation_repo.reconcile_orphaned_investigations(session)
                for inv_id in orphaned_ids:
                    await self.audit_repo.log_event(
                        session=session,
                        actor_id="system",
                        action="CRASH_RECOVERY_RECONCILED",
                        resource_type="investigation",
                        resource_id=inv_id,
                        outcome="FAILURE",
                        request_id="startup-reconciliation",
                        client_ip="127.0.0.1",
                        metadata={
                            "reason": "ORPHANED_PROCESS_CRASH",
                            "description": "Investigation was in progress when backend process terminated unexpectedly.",
                        },
                    )

        if orphaned_ids:
            logger.warning(
                "Startup crash recovery: reconciled %d orphaned investigation(s) with ORPHANED_PROCESS_CRASH",
                len(orphaned_ids),
            )
        else:
            logger.debug("Startup crash recovery: zero orphaned investigations found")

        return len(orphaned_ids)

    async def record_feedback(
        self,
        investigation_id: str,
        rating: str,
        notes: Optional[str] = None,
        actor_id: str = "local_analyst",
        request_id: str = "req-unknown",
        client_ip: str = "127.0.0.1",
    ) -> Optional[Investigation]:
        """Record analyst evaluation rating and optional commentary with audit log."""
        async with self.session_factory() as session:
            async with session.begin():
                inv = await self.investigation_repo.submit_feedback(
                    session=session,
                    investigation_id=investigation_id,
                    analyst_rating=rating,
                    analyst_notes=notes,
                )
                if inv is None:
                    return None

                await self.audit_repo.log_event(
                    session=session,
                    actor_id=actor_id,
                    action="INVESTIGATION_FEEDBACK_SUBMITTED",
                    resource_type="investigation",
                    resource_id=investigation_id,
                    outcome="SUCCESS",
                    request_id=request_id,
                    client_ip=client_ip,
                    metadata={
                        "alert_id": inv.alert_id,
                        "rating": rating,
                        "has_notes": bool(notes),
                    },
                )
                return inv

