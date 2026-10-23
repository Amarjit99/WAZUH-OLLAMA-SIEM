"""Unit and integration tests for Analyst-Approved Containment & Active Response."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings
from app.core.errors import AppException
from app.db.session import get_session_factory
from app.main import create_app
from app.schemas.containment import (
    ContainmentActionType,
    ContainmentExecutionRequest,
    ContainmentProposalRequest,
)
from app.services.containment_service import ContainmentService


@pytest.fixture
def containment_service():
    settings = Settings()
    return ContainmentService(settings=settings)


def test_propose_containment_with_ip(containment_service):
    """Verify proposal generator creates BLOCK_IP playbook with platform commands."""
    req = ContainmentProposalRequest(
        alert_id="test-alert-1",
        source_ip="203.0.113.55",
        agent_name="db-prod-01",
    )
    res = containment_service.propose_containment(req)

    assert len(res.proposed_actions) >= 2
    ip_action = next(a for a in res.proposed_actions if a.action_type == ContainmentActionType.BLOCK_IP)
    assert ip_action.target == "203.0.113.55"
    assert len(ip_action.commands) == 4
    # Check platforms covered
    platforms = [c.platform.value for c in ip_action.commands]
    assert "LINUX_IPTABLES" in platforms
    assert "LINUX_NFTABLES" in platforms
    assert "WINDOWS_NETSH" in platforms
    assert "WAZUH_ACTIVE_RESPONSE" in platforms


def test_propose_containment_rejects_loopback(containment_service):
    """Verify loopback addresses (127.0.0.1) are excluded from block proposals to prevent lockout."""
    req = ContainmentProposalRequest(source_ip="127.0.0.1")
    res = containment_service.propose_containment(req)
    assert len(res.proposed_actions) == 0


def test_propose_containment_host_isolation(containment_service):
    """Verify proposal generator creates ISOLATE_HOST playbook."""
    req = ContainmentProposalRequest(agent_name="compromised-srv-01")
    res = containment_service.propose_containment(req)

    assert len(res.proposed_actions) == 1
    action = res.proposed_actions[0]
    assert action.action_type == ContainmentActionType.ISOLATE_HOST
    assert action.target == "compromised-srv-01"
    assert any("/var/ossec/bin/agent_control" in c.command for c in action.commands)


@pytest.mark.asyncio
async def test_containment_execution_requires_analyst_approval(containment_service):
    """Verify action is strictly rejected if human analyst_approval is False."""
    req = ContainmentExecutionRequest(
        action_type=ContainmentActionType.BLOCK_IP,
        target="198.51.100.10",
        rationale="Brute-force SSH attack detected",
        analyst_id="soc-analyst-bob",
        analyst_approval=False,
    )
    session_factory = get_session_factory()
    async with session_factory() as session:
        with pytest.raises(AppException) as exc_info:
            await containment_service.approve_and_log_containment(
                request=req,
                session=session,
                request_id="req-test-1",
                client_ip="127.0.0.1",
            )
        assert exc_info.value.code.value == "VALIDATION_ERROR"
        assert "Human analyst approval is required" in exc_info.value.message


@pytest.mark.asyncio
async def test_containment_execution_logs_tamper_evident_audit(containment_service):
    """Verify approved containment generates commands and logs cryptographic audit event."""
    req = ContainmentExecutionRequest(
        action_type=ContainmentActionType.BLOCK_IP,
        target="198.51.100.25",
        rationale="Command and Control beaconing confirmed",
        analyst_id="soc-lead-alice",
        analyst_approval=True,
    )
    session_factory = get_session_factory()
    async with session_factory() as session:
        res = await containment_service.approve_and_log_containment(
            request=req,
            session=session,
            request_id="req-audit-test",
            client_ip="127.0.0.1",
        )

    assert res.status == "APPROVED_AND_LOGGED"
    assert res.analyst_id == "soc-lead-alice"
    assert res.audit_id is not None
    assert len(res.generated_commands) == 4


@pytest.mark.asyncio
async def test_containment_api_integration():
    """Verify /api/v1/containment/propose and /execute HTTP routes."""
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        # 1. Propose
        prop_resp = await client.post(
            "/api/v1/containment/propose",
            json={"source_ip": "198.51.100.77", "agent_name": "srv-web-01"},
        )
        assert prop_resp.status_code == 200
        prop_data = prop_resp.json()
        assert len(prop_data["proposed_actions"]) >= 2

        # 2. Execute with approval
        exec_resp = await client.post(
            "/api/v1/containment/execute",
            json={
                "action_type": "BLOCK_IP",
                "target": "198.51.100.77",
                "rationale": "High-severity rootkit attack C2 IP",
                "analyst_id": "soc-analyst-charlie",
                "analyst_approval": True,
            },
        )
        assert exec_resp.status_code == 200
        exec_data = exec_resp.json()
        assert exec_data["status"] == "APPROVED_AND_LOGGED"
        assert exec_data["audit_id"] is not None

        # 3. History
        hist_resp = await client.get("/api/v1/containment/history?limit=5")
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        assert len(hist_data) >= 1
        assert any(item["target"] == "198.51.100.77" for item in hist_data)
