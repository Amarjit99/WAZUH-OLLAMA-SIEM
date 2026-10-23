"""Pydantic schemas for SOC alert notifications and webhooks."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class AlertNotificationPayload(BaseModel):
    """Normalized payload sent to external webhook endpoints."""

    event_type: str = Field(default="high_severity_alert", description="Notification event category")
    timestamp: str = Field(description="Alert occurrence timestamp in UTC")
    alert_id: str = Field(description="Unique alert identifier")
    rule_id: str = Field(description="Wazuh rule ID")
    rule_description: str = Field(description="Descriptive explanation of the detected rule")
    rule_level: int = Field(description="Wazuh severity level (1-15)")
    agent_id: Optional[str] = Field(default=None, description="Affected agent ID")
    agent_name: Optional[str] = Field(default=None, description="Affected agent host name")
    source_ip: Optional[str] = Field(default=None, description="Source IP address if detected")
    location: Optional[str] = Field(default=None, description="Log file or decoder location")
    dashboard_url: str = Field(default="http://127.0.0.1:5174", description="Link to Analyst Dashboard")


class NotificationTestRequest(BaseModel):
    """Request payload for manual webhook delivery test."""

    webhook_url: Optional[str] = Field(default=None, description="Optional override URL for test dispatch")


class NotificationTestResponse(BaseModel):
    """Result of webhook delivery test."""

    status: str = Field(description="Dispatch status: 'delivered', 'failed', or 'disabled'")
    message: str = Field(description="Operational outcome or reason")
    target_masked: Optional[str] = Field(default=None, description="Masked target endpoint URL")
    dispatched_at: datetime = Field(description="UTC timestamp of the attempt")
