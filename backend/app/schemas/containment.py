"""Pydantic schemas for SOC analyst-approved active response and containment playbooks."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ContainmentActionType(str, Enum):
    """Categorization of incident containment actions."""

    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    KILL_PROCESS = "KILL_PROCESS"
    DISABLE_USER = "DISABLE_USER"


class ContainmentPlatform(str, Enum):
    """Target enforcement platform or firewall architecture."""

    LINUX_IPTABLES = "LINUX_IPTABLES"
    LINUX_NFTABLES = "LINUX_NFTABLES"
    WINDOWS_NETSH = "WINDOWS_NETSH"
    WAZUH_ACTIVE_RESPONSE = "WAZUH_ACTIVE_RESPONSE"


class GeneratedCommand(BaseModel):
    """Platform-specific containment command or rule."""

    platform: ContainmentPlatform = Field(description="Target platform syntax")
    command: str = Field(description="Exact executable command line or rule syntax")
    description: str = Field(description="Operational summary of what this command enforces")


class ContainmentProposalRequest(BaseModel):
    """Parameters to generate containment options."""

    alert_id: Optional[str] = Field(default=None, description="Related Wazuh alert ID")
    investigation_id: Optional[str] = Field(default=None, description="Related AI investigation ID")
    source_ip: Optional[str] = Field(default=None, description="Identified malicious source IP")
    agent_id: Optional[str] = Field(default=None, description="Target Wazuh agent ID")
    agent_name: Optional[str] = Field(default=None, description="Target host name")
    process_name: Optional[str] = Field(default=None, description="Target process name or PID")


class ProposedContainmentAction(BaseModel):
    """Individual containment recommendation proposed to the analyst."""

    action_type: ContainmentActionType = Field(description="Action category")
    target: str = Field(description="Target entity (IP address, hostname, process)")
    rationale: str = Field(description="Security justification for this containment action")
    risk_level: str = Field(description="Operational collateral risk level: LOW, MEDIUM, or HIGH")
    commands: List[GeneratedCommand] = Field(default_factory=list, description="Platform-tailored commands")


class ContainmentProposalResponse(BaseModel):
    """Collection of containment options available for analyst review."""

    proposed_actions: List[ProposedContainmentAction] = Field(default_factory=list)
    generated_at: datetime = Field(description="UTC timestamp of proposal generation")


class ContainmentExecutionRequest(BaseModel):
    """Human-in-the-loop explicit approval request."""

    action_type: ContainmentActionType = Field(description="Containment action category")
    target: str = Field(description="Target entity to contain")
    rationale: str = Field(description="Analyst reasoning for authorizing this containment action")
    analyst_id: str = Field(default="analyst-1", description="Identifier of the approving analyst")
    analyst_approval: bool = Field(
        description="Explicit human approval gate. Must be True or action is rejected."
    )
    alert_id: Optional[str] = Field(default=None, description="Associated alert ID")
    investigation_id: Optional[str] = Field(default=None, description="Associated investigation ID")


class ContainmentExecutionResponse(BaseModel):
    """Audited outcome of analyst containment authorization."""

    execution_id: str = Field(description="Unique ID of this containment authorization record")
    action_type: ContainmentActionType = Field(description="Containment action category")
    target: str = Field(description="Target entity contained")
    status: str = Field(description="Approval status: APPROVED_AND_LOGGED")
    generated_commands: List[GeneratedCommand] = Field(description="Platform-specific commands generated")
    audit_id: str = Field(description="Cryptographic SHA-256 audit chain event ID")
    approved_at: datetime = Field(description="UTC timestamp of approval")
    analyst_id: str = Field(description="Approving analyst ID")
    message: str = Field(description="Confirmation notice for the SOC analyst")
