"""Health check schemas adhering to specs/API_CONTRACT.md and specs/PRD.md."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ServiceStatus(str, Enum):
    """Overall service status."""
    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class DependencyStatus(str, Enum):
    """Integration dependency status per FR-005."""
    CONNECTED = "connected"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"


class DependencyHealth(BaseModel):
    """Health check outcome for an individual upstream dependency."""
    status: DependencyStatus = Field(..., description="Connection status")
    message: str = Field(..., description="Safe diagnostic message without secrets")
    latency_ms: Optional[float] = Field(default=None, description="Check probe latency in milliseconds")


class HealthLiveResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="ok", description="Process liveness state")


class HealthReadyResponse(BaseModel):
    """Readiness probe response with real dependency statuses."""
    status: ServiceStatus = Field(..., description="Overall readiness status")
    dependencies: Dict[str, DependencyHealth] = Field(
        ...,
        description="Individual status for Wazuh API, OpenSearch, and Ollama",
    )
    retrieved_at: datetime = Field(..., description="Timestamp of probe execution in UTC")
    request_id: str = Field(..., description="Correlation request ID")


class BackupOperationalStatusResponse(BaseModel):
    """Operational status response for database backups, encryption, and recovery."""
    status: str = Field(..., description="Overall backup subsystem health: OK, DEGRADED, or UNAVAILABLE")
    scheduler_enabled: bool = Field(..., description="Whether periodic backup scheduler is enabled in config")
    scheduler_active: bool = Field(..., description="Whether periodic backup background loop is running")
    is_backup_in_progress: bool = Field(..., description="Whether a backup operation is currently executing")
    backup_interval_minutes: int = Field(..., description="Configured interval between automated backups")
    last_backup_attempt_at: Optional[datetime] = Field(default=None, description="Timestamp of most recent backup attempt")
    last_successful_backup_at: Optional[datetime] = Field(default=None, description="Timestamp of most recent successful backup")
    last_backup_duration_seconds: Optional[float] = Field(default=None, description="Duration in seconds of last backup attempt")
    last_backup_verification_status: str = Field(..., description="Verification outcome of last backup: VERIFIED, FAILED, or UNVERIFIED")
    last_backup_error: Optional[str] = Field(default=None, description="Error message from last failed backup, if any")
    last_backup_error_category: Optional[str] = Field(default=None, description="Failure category: CORRUPTION, CRYPTO, TIMEOUT, PERMISSION, etc.")
    last_backup_encrypted: Optional[bool] = Field(default=None, description="Whether last completed backup was encrypted")
    encryption_key_status: Dict[str, Any] = Field(..., description="Safe key availability metadata (zero secret key bytes)")
    last_recovery_drill_at: Optional[datetime] = Field(default=None, description="Timestamp of most recent recovery drill")
    last_recovery_drill_status: str = Field(..., description="Status of recovery test: VERIFIED, FAILED, or NEVER_RUN")
    last_audit_verification_at: Optional[datetime] = Field(default=None, description="Timestamp of most recent audit verification")
    last_audit_verification_status: str = Field(default="UNVERIFIED", description="Status of audit verification: VERIFIED, FAILED, or UNVERIFIED")
    last_audit_events_verified: Optional[int] = Field(default=None, description="Count of contiguous audit events verified")
    last_audit_error: Optional[str] = Field(default=None, description="Audit chain verification error if broken")
    retrieved_at: datetime = Field(..., description="Status retrieval timestamp in UTC")


class AuditVerificationStatusResponse(BaseModel):
    """Integrity check report for cryptographic audit hash chain."""
    status: str = Field(..., description="Integrity status: VERIFIED, FAILED, or UNVERIFIED")
    verified_events_count: int = Field(default=0, description="Count of contiguous audit events validated")
    active_checkpoint_sequence: Optional[int] = Field(default=None, description="Active checkpoint sequence if present")
    error: Optional[str] = Field(default=None, description="Error reason if chain broken")
    verified_at: datetime = Field(..., description="Timestamp of verification execution in UTC")
