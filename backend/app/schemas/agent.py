"""Pydantic schemas for Wazuh agent fleet monitoring."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentOSInfo(BaseModel):
    """Operating system telemetry of an enrolled agent."""

    name: Optional[str] = Field(default=None, description="Operating system distribution or name")
    version: Optional[str] = Field(default=None, description="OS version")
    platform: Optional[str] = Field(default=None, description="Platform identifier (e.g. amzn, debian, windows)")
    arch: Optional[str] = Field(default=None, description="CPU architecture (e.g. x86_64, arm64)")
    uname: Optional[str] = Field(default=None, description="Detailed kernel/uname release string")


class AgentItem(BaseModel):
    """Individual Wazuh monitored agent details."""

    id: str = Field(description="Unique agent ID assigned by Wazuh Manager")
    name: str = Field(description="Host or agent name")
    ip: Optional[str] = Field(default=None, description="Agent source or registration IP")
    status: str = Field(description="Connection status (active, disconnected, never_connected, pending)")
    version: Optional[str] = Field(default=None, description="Wazuh agent version string")
    node_name: Optional[str] = Field(default=None, description="Manager cluster node handling the agent")
    date_add: Optional[str] = Field(default=None, description="Timestamp when agent was enrolled")
    last_keep_alive: Optional[str] = Field(default=None, description="Last keep-alive signal timestamp")
    os: Optional[AgentOSInfo] = Field(default=None, description="OS and kernel details")


class AgentSummary(BaseModel):
    """Aggregate fleet connection statistics."""

    total: int = Field(default=0, description="Total registered agents")
    active: int = Field(default=0, description="Agents currently connected and reporting")
    disconnected: int = Field(default=0, description="Enrolled agents currently offline")
    never_connected: int = Field(default=0, description="Agents registered but never connected")
    pending: int = Field(default=0, description="Agents in pending authorization state")


class AgentListResponse(BaseModel):
    """Fleet overview response conforming to specs/API_CONTRACT.md."""

    items: List[AgentItem] = Field(default_factory=list, description="List of monitored endpoint agents")
    summary: AgentSummary = Field(description="Fleet status summary counts")
    total_items: int = Field(description="Total agents matching query")
    retrieved_at: datetime = Field(description="UTC timestamp of fleet telemetry retrieval")
