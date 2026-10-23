"""Pydantic schemas for Case Management API."""

from datetime import datetime
from typing import List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field

CaseStatus = Literal["open", "in_progress", "resolved", "closed"]
CasePriority = Literal["low", "medium", "high", "critical"]


class CaseCreate(BaseModel):
    """Payload to create a new case."""
    title: str = Field(min_length=1, max_length=255, description="Case title")
    description: Optional[str] = Field(default=None, max_length=4096, description="Case description")
    priority: CasePriority = Field(default="medium", description="Case priority level")
    assignee: Optional[str] = Field(default=None, max_length=128, description="Assigned analyst")
    alert_id: Optional[str] = Field(default=None, max_length=128, description="Associated Wazuh alert ID")
    investigation_id: Optional[str] = Field(default=None, max_length=64, description="Associated investigation ID")
    analyst_notes: Optional[str] = Field(default=None, max_length=4096, description="Initial analyst notes")


class CaseUpdate(BaseModel):
    """Payload to update an existing case."""
    title: Optional[str] = Field(default=None, min_length=1, max_length=255, description="Updated case title")
    description: Optional[str] = Field(default=None, max_length=4096, description="Updated description")
    status: Optional[CaseStatus] = Field(default=None, description="Updated status")
    priority: Optional[CasePriority] = Field(default=None, description="Updated priority")
    assignee: Optional[str] = Field(default=None, max_length=128, description="Updated assignee")
    analyst_notes: Optional[str] = Field(default=None, max_length=4096, description="Appended or updated analyst notes")


class CaseResponse(BaseModel):
    """Response representation of a Case."""
    model_config = ConfigDict(from_attributes=True)

    case_id: str = Field(description="Unique case ID (e.g. CASE-YYYYMMDD-XXXXXX)")
    title: str = Field(description="Case title")
    description: Optional[str] = Field(default=None, description="Detailed case description")
    status: str = Field(description="Status: open, in_progress, resolved, closed")
    priority: str = Field(description="Priority: low, medium, high, critical")
    assignee: Optional[str] = Field(default=None, description="Assigned analyst")
    alert_id: Optional[str] = Field(default=None, description="Associated alert ID")
    investigation_id: Optional[str] = Field(default=None, description="Associated investigation ID")
    analyst_notes: Optional[str] = Field(default=None, description="Analyst commentary and notes")
    created_at: datetime = Field(description="Creation UTC timestamp")
    updated_at: datetime = Field(description="Last update UTC timestamp")
    closed_at: Optional[datetime] = Field(default=None, description="Resolution/closure UTC timestamp")


class CasePagination(BaseModel):
    """Pagination metadata for cases."""
    page: int = Field(ge=1, description="Current page number")
    page_size: int = Field(ge=1, le=100, description="Items per page")
    total_items: int = Field(ge=0, description="Total matching cases count")
    total_pages: int = Field(ge=0, description="Total pages available")
    has_next: bool = Field(description="True if next page exists")
    has_prev: bool = Field(description="True if previous page exists")


class CaseListResponse(BaseModel):
    """Response envelope for GET /api/v1/cases."""
    items: List[CaseResponse] = Field(description="Page of case items")
    pagination: CasePagination = Field(description="Pagination metadata")
    request_id: str = Field(description="Correlation request ID")
