"""Pydantic schemas for Investigation History and Detail API conforming to specs/PHASE_7_API_CONTRACT.md."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.investigation import (
    ConfidenceLabel,
    Hypothesis,
    ObservedFact,
    PriorityLevel,
    RecommendedCheck,
    UncertaintyLevel,
)


class InvestigationSummaryItem(BaseModel):
    """Summary item for investigation history list."""
    model_config = ConfigDict(extra="ignore")

    investigation_id: str = Field(description="Unique investigation identifier (UUIDv4)")
    alert_id: str = Field(description="Associated authoritative Wazuh alert ID")
    run_sequence: int = Field(description="Sequential execution counter for this alert (1, 2, 3...)")
    status: str = Field(description="Lifecycle status: queued, running, completed, failed, cancelled")
    primary_rule_id: str = Field(description="Primary Wazuh alert rule ID")
    primary_rule_level: Optional[int] = Field(default=None, description="Primary rule severity level")
    primary_agent_name: Optional[str] = Field(default=None, description="Primary monitored agent name")
    model_name: Optional[str] = Field(default=None, description="AI model family name if completed")
    model_tag: Optional[str] = Field(default=None, description="AI model tag version if completed")
    confidence_label: Optional[str] = Field(default=None, description="Qualitative confidence label")
    correlation_status: Optional[str] = Field(default=None, description="Correlation outcome status")
    evidence_count: int = Field(default=0, description="Count of evaluated evidence snapshots")
    execution_duration_ms: Optional[int] = Field(default=None, description="Execution duration in milliseconds")
    error_code: Optional[str] = Field(default=None, description="Safe error code if failed")
    error_message: Optional[str] = Field(default=None, description="Safe failure description if failed")
    created_at: datetime = Field(description="Creation UTC timestamp")
    updated_at: datetime = Field(description="Last update UTC timestamp")
    actor_id: str = Field(default="local_analyst", description="Triggering analyst or process identifier")
    analyst_rating: Optional[str] = Field(default=None, description="Analyst feedback rating: helpful, incorrect, incomplete")
    analyst_notes: Optional[str] = Field(default=None, description="Analyst feedback commentary")
    feedback_submitted_at: Optional[datetime] = Field(default=None, description="UTC timestamp when feedback was recorded")


class InvestigationPagination(BaseModel):
    """Pagination metadata for investigation history."""
    page: int = Field(ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(ge=1, le=100, description="Items per page")
    total_items: int = Field(ge=0, description="Total matching investigations count")
    total_pages: int = Field(ge=0, description="Total pages available")
    has_next: bool = Field(description="True if next page exists")
    has_prev: bool = Field(description="True if previous page exists")


class InvestigationListResponse(BaseModel):
    """Response envelope for GET /api/v1/investigations."""
    items: List[InvestigationSummaryItem] = Field(description="Page of investigation summaries")
    pagination: InvestigationPagination = Field(description="Pagination metadata")
    request_id: str = Field(description="Correlation request ID")


class InvestigationFeedbackRequest(BaseModel):
    """Payload for submitting analyst feedback on an AI investigation."""
    rating: str = Field(description="Rating value: helpful, incorrect, incomplete")
    notes: Optional[str] = Field(default=None, max_length=2048, description="Optional analyst commentary or critique")


class EvidenceSnapshotItem(BaseModel):
    """Forensic evidence snapshot evaluated during inference."""
    model_config = ConfigDict(extra="ignore")

    evidence_id: str = Field(description="Stable reference identifier (e.g. EV-01)")
    source_record_id: str = Field(description="Underlying alert or log record ID")
    event_timestamp: datetime = Field(description="Event timestamp in UTC")
    is_primary: bool = Field(description="True if this is the investigated anchor alert")
    rule_id: str = Field(description="Rule identifier")
    rule_level: Optional[int] = Field(default=None, description="Rule severity level")
    rule_description: Optional[str] = Field(default=None, description="Human-readable rule title")
    agent_name: Optional[str] = Field(default=None, description="Monitored agent hostname")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address")
    username: Optional[str] = Field(default=None, description="Associated username")
    correlation_reason: Optional[str] = Field(default=None, description="Reason for correlation")
    correlation_qualifier: Optional[str] = Field(default=None, description="Qualifying context")
    raw_evidence_ref: str = Field(description="Safe pointer to authoritative index and record")


class InvestigationDetailResult(BaseModel):
    """Structured AI output and findings for a completed investigation."""
    model_config = ConfigDict(extra="ignore")

    model_name: str = Field(description="Model family name")
    model_tag: str = Field(description="Configured model tag version")
    prompt_version: str = Field(default="v1.0", description="Prompt template version")
    summary: str = Field(description="High-level narrative findings summary")
    confidence_label: str = Field(description="Confidence rating: low, medium, high, unverified")
    disclaimer: str = Field(description="Advisory analysis disclaimer")
    observed_facts: List[ObservedFact] = Field(default_factory=list, description="Observed facts with citations")
    hypotheses: List[Hypothesis] = Field(default_factory=list, description="Hypotheses with uncertainty")
    recommended_checks: List[RecommendedCheck] = Field(default_factory=list, description="Defensive read-only checks")
    limitations: List[str] = Field(default_factory=list, description="Known context limitations or gaps")
    unsupported_citation_warnings: List[str] = Field(default_factory=list, description="Citation validation warnings")
    correlation_status: Optional[str] = Field(default=None, description="Correlation outcome status")


class InvestigationDetailResponse(BaseModel):
    """Response envelope for GET /api/v1/investigations/{investigation_id}."""
    model_config = ConfigDict(extra="ignore")

    investigation_id: str = Field(description="Unique investigation identifier (UUIDv4)")
    alert_id: str = Field(description="Investigated alert ID")
    run_sequence: int = Field(description="Run sequence number for this alert")
    status: str = Field(description="Investigation status: queued, running, completed, failed, cancelled")
    primary_rule_id: str = Field(description="Primary rule ID")
    primary_rule_level: Optional[int] = Field(default=None, description="Primary rule level")
    primary_agent_name: Optional[str] = Field(default=None, description="Primary agent name")
    query_window_minutes: int = Field(description="Correlation query window in minutes")
    max_evidence_items: int = Field(description="Maximum evidence items allowed")
    error_code: Optional[str] = Field(default=None, description="Error code if investigation failed")
    error_message: Optional[str] = Field(default=None, description="Safe error description if failed")
    execution_duration_ms: Optional[int] = Field(default=None, description="Duration in ms")
    created_at: datetime = Field(description="Creation UTC timestamp")
    updated_at: datetime = Field(description="Last update UTC timestamp")
    actor_id: str = Field(description="Triggering user or process ID")
    analyst_rating: Optional[str] = Field(default=None, description="Analyst feedback rating: helpful, incorrect, incomplete")
    analyst_notes: Optional[str] = Field(default=None, description="Analyst feedback commentary")
    feedback_submitted_at: Optional[datetime] = Field(default=None, description="UTC timestamp when feedback was recorded")
    result: Optional[InvestigationDetailResult] = Field(default=None, description="AI findings if completed")
    evidence_items: List[EvidenceSnapshotItem] = Field(default_factory=list, description="Evaluated evidence snapshots")
    request_id: str = Field(description="Correlation request ID")

