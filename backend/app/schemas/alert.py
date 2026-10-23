"""Normalized alert data models adhering to specs/DATA_SCHEMA.md and specs/API_CONTRACT.md."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class DataStatus(str, Enum):
    """Data freshness and completeness indicator."""

    FRESH = "fresh"
    STALE = "stale"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class NormalizedAlert(BaseModel):
    """Canonical representation of a security alert retrieved from Wazuh / OpenSearch."""

    model_config = ConfigDict(extra="ignore")

    alert_id: str = Field(description="Stable source document or alert identifier")
    source_system: str = Field(default="Wazuh", description="Originating detection authority")
    source_index: str = Field(description="Underlying OpenSearch index or collection")
    timestamp: datetime = Field(description="Normalized UTC event timestamp")
    retrieved_at: datetime = Field(description="UTC timestamp when backend retrieved the record")
    rule_id: str = Field(description="Source rule identifier preserved as string")
    rule_description: str = Field(default="", description="Human-readable rule description")
    rule_level: Optional[int] = Field(default=None, description="Source rule severity level (1-16)")
    agent_id: Optional[str] = Field(default=None, description="Monitored agent identifier")
    agent_name: Optional[str] = Field(default=None, description="Monitored agent hostname or label")
    host_name: Optional[str] = Field(default=None, description="Manager or reporting host name")
    source_ip: Optional[str] = Field(default=None, description="Source IP address if applicable")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address if applicable")
    username: Optional[str] = Field(default=None, description="Associated account or user identity")
    event_type: Optional[str] = Field(default=None, description="Event classification or category")
    location: Optional[str] = Field(default=None, description="Source log file, socket, or channel")
    decoder_name: Optional[str] = Field(default=None, description="Wazuh decoder name that parsed the event")
    full_log: Optional[str] = Field(default=None, description="Raw log message if available")
    raw_document: Optional[Dict[str, Any]] = Field(default=None, description="Raw document payload if available")
    raw_evidence_ref: str = Field(description="Safe pointer to source record without dumping raw secrets")
    normalization_warnings: List[str] = Field(
        default_factory=list,
        description="Non-fatal field normalization notes or missing optional fields",
    )


class QueryWindow(BaseModel):
    """Bounded query time window for alert searches."""

    start_time: datetime = Field(description="Inclusive start timestamp in UTC")
    end_time: datetime = Field(description="Inclusive end timestamp in UTC")


class PaginationMetadata(BaseModel):
    """Bounded pagination details."""

    page: int = Field(ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(ge=1, le=100, description="Number of items per page")
    total_items: int = Field(ge=0, description="Total matching alert count")
    total_pages: int = Field(ge=0, description="Total pages available")
    has_more: bool = Field(description="True if additional pages exist")


class AlertListResponse(BaseModel):
    """API envelope for alert queries conforming to specs/API_CONTRACT.md."""

    items: List[NormalizedAlert] = Field(default_factory=list, description="List of normalized alert records")
    pagination: PaginationMetadata = Field(description="Pagination control metadata")
    query_window: QueryWindow = Field(description="Effective search time range")
    retrieved_at: datetime = Field(description="Time of retrieval in UTC")
    data_status: DataStatus = Field(default=DataStatus.FRESH, description="Data freshness indicator")
    request_id: Optional[str] = Field(default=None, description="Request correlation ID")
