"""Wazuh agent fleet management and monitoring API endpoints."""

from datetime import datetime, timezone
import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query

from app.api.deps import get_wazuh_client, verify_api_auth
from app.core.errors import AppException
from app.schemas.agent import (
    AgentItem,
    AgentListResponse,
    AgentOSInfo,
    AgentSummary,
)
from app.schemas.error import ErrorCode
from app.services.wazuh_client import WazuhClient

logger = logging.getLogger("siem.api.agents")
router = APIRouter(prefix="/agents", tags=["Agents"])


@router.get("", response_model=AgentListResponse, summary="List monitored Wazuh agents")
async def list_agents(
    limit: int = Query(default=20, ge=1, le=100, description="Page limit (1-100)"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    status: Optional[str] = Query(default=None, description="Optional status filter (e.g. active, disconnected)"),
    wazuh_client: WazuhClient = Depends(get_wazuh_client),
    _authorized: bool = Depends(verify_api_auth),
) -> AgentListResponse:
    """Retrieve monitored agent fleet telemetry from Wazuh Manager API."""
    try:
        raw_res = await wazuh_client.get_agents(limit=limit, offset=offset)
    except AppException:
        raise
    except Exception as err:
        logger.error("Failed to query agents from Wazuh API: %s", err)
        raise AppException(
            code=ErrorCode.DEPENDENCY_UNAVAILABLE,
            message="Wazuh Manager API is unavailable or agent retrieval failed",
            status_code=503,
        ) from err

    affected_items = raw_res.get("data", {}).get("affected_items", [])
    total_items = raw_res.get("data", {}).get("total_affected_items", len(affected_items))

    # Parse individual agent records
    agents = []
    active_count = 0
    disconnected_count = 0
    never_connected_count = 0
    pending_count = 0

    for item in affected_items:
        agent_status = str(item.get("status", "unknown")).lower()
        if agent_status == "active":
            active_count += 1
        elif agent_status in ("disconnected", "offline"):
            disconnected_count += 1
        elif agent_status == "never_connected":
            never_connected_count += 1
        elif agent_status == "pending":
            pending_count += 1

        # Apply in-memory status filter if requested
        if status and agent_status != status.lower():
            continue

        os_data = item.get("os", {})
        os_info = None
        if os_data and isinstance(os_data, dict):
            os_info = AgentOSInfo(
                name=os_data.get("name"),
                version=os_data.get("version"),
                platform=os_data.get("platform"),
                arch=os_data.get("arch"),
                uname=os_data.get("uname"),
            )

        agents.append(
            AgentItem(
                id=str(item.get("id", "000")),
                name=str(item.get("name", "Unknown")),
                ip=item.get("ip") or item.get("registerIP"),
                status=agent_status,
                version=item.get("version"),
                node_name=item.get("node_name"),
                date_add=item.get("dateAdd"),
                last_keep_alive=item.get("lastKeepAlive"),
                os=os_info,
            )
        )

    summary = AgentSummary(
        total=total_items,
        active=active_count,
        disconnected=disconnected_count,
        never_connected=never_connected_count,
        pending=pending_count,
    )

    return AgentListResponse(
        items=agents,
        summary=summary,
        total_items=len(agents) if status else total_items,
        retrieved_at=datetime.now(timezone.utc),
    )
