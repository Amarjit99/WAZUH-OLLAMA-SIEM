"""SQLAlchemy 2.0 ORM models for investigations, results, facts, hypotheses, checks, and evidence snapshots.

Conforms strictly to specs/PHASE_7_DATABASE_SCHEMA.md.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """Generate a UUID4 hex string."""
    return str(uuid.uuid4())


class Investigation(Base):
    """Authoritative record for an alert investigation lifecycle and execution attempt."""

    __tablename__ = "investigations"

    investigation_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    alert_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    run_sequence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="queued",
    )
    primary_rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    primary_rule_level: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    primary_agent_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    query_window_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=30,
    )
    max_evidence_items: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=10,
    )
    error_code: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    execution_duration_ms: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    actor_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="local_analyst",
    )
    analyst_rating: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    analyst_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    feedback_submitted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    result: Mapped[Optional["InvestigationResult"]] = relationship(
        "InvestigationResult",
        back_populates="investigation",
        cascade="all, delete-orphan",
        uselist=False,
    )
    evidence_snapshots: Mapped[List["InvestigationEvidenceSnapshot"]] = relationship(
        "InvestigationEvidenceSnapshot",
        back_populates="investigation",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("alert_id", "run_sequence", name="uq_alert_run"),
        Index("idx_investigations_alert_id", "alert_id"),
        Index("idx_investigations_created_at", created_at.desc()),
        Index("idx_investigations_status", "status"),
        Index("idx_investigations_rule", "primary_rule_id"),
        Index("idx_investigations_agent", "primary_agent_name"),
        Index("idx_investigations_actor", "actor_id"),
    )


class InvestigationResult(Base):
    """Advisory AI-generated synthesis output for completed investigations."""

    __tablename__ = "investigation_results"

    result_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    investigation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigations.investigation_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    model_name: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    model_tag: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    prompt_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    confidence_label: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    disclaimer: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    limitations_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )
    warnings_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )
    correlation_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="result",
    )
    facts: Mapped[List["InvestigationFact"]] = relationship(
        "InvestigationFact",
        back_populates="result",
        cascade="all, delete-orphan",
    )
    hypotheses: Mapped[List["InvestigationHypothesis"]] = relationship(
        "InvestigationHypothesis",
        back_populates="result",
        cascade="all, delete-orphan",
    )
    checks: Mapped[List["InvestigationCheck"]] = relationship(
        "InvestigationCheck",
        back_populates="result",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("investigation_id", name="uq_result_investigation"),
        Index("idx_results_confidence", "confidence_label"),
    )


class InvestigationFact(Base):
    """Discrete factual statement corroborated by evidence citations."""

    __tablename__ = "investigation_facts"

    fact_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    result_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigation_results.result_id", ondelete="CASCADE"),
        nullable=False,
    )
    fact_identifier: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    statement: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    cited_evidence_ids_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )

    # Relationships
    result: Mapped["InvestigationResult"] = relationship(
        "InvestigationResult",
        back_populates="facts",
    )

    __table_args__ = (
        Index("idx_facts_result", "result_id"),
    )


class InvestigationHypothesis(Base):
    """Advisory hypothesis and uncertainty assessment generated by LLM."""

    __tablename__ = "investigation_hypotheses"

    hypothesis_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    result_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigation_results.result_id", ondelete="CASCADE"),
        nullable=False,
    )
    hypothesis_identifier: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    statement: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    uncertainty: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    cited_evidence_ids_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )

    # Relationships
    result: Mapped["InvestigationResult"] = relationship(
        "InvestigationResult",
        back_populates="hypotheses",
    )

    __table_args__ = (
        Index("idx_hypotheses_result", "result_id"),
    )


class InvestigationCheck(Base):
    """Recommended verification check for SOC analyst action."""

    __tablename__ = "investigation_checks"

    check_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    result_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigation_results.result_id", ondelete="CASCADE"),
        nullable=False,
    )
    check_identifier: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    rationale: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    priority: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    is_read_only: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    # Relationships
    result: Mapped["InvestigationResult"] = relationship(
        "InvestigationResult",
        back_populates="checks",
    )

    __table_args__ = (
        Index("idx_checks_result", "result_id"),
    )


class InvestigationEvidenceSnapshot(Base):
    """Forensic evidence snapshot preserving evaluated fields at time of inference."""

    __tablename__ = "investigation_evidence_snapshots"

    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    investigation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("investigations.investigation_id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_id: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    source_record_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    is_primary: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    rule_level: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    rule_description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    agent_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    source_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    destination_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    username: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    correlation_reason: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    correlation_qualifier: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    raw_evidence_ref: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="evidence_snapshots",
    )

    __table_args__ = (
        UniqueConstraint("investigation_id", "evidence_id", name="uq_investigation_evidence"),
        Index("idx_snapshots_investigation", "investigation_id"),
        Index("idx_snapshots_source_record", "source_record_id"),
    )
