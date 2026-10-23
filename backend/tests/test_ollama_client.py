"""Unit tests for OllamaClient and EvidenceService conforming to Phase 3B mandate."""

import asyncio
from datetime import datetime, timezone
import json
import pytest
import httpx

from app.core.config import Settings
from app.core.errors import AppException
from app.schemas.alert import NormalizedAlert
from app.schemas.investigation import (
    ConfidenceLabel,
    EvidenceItem,
    EvidencePackage,
    InvestigationStatus,
    UncertaintyLevel,
    validate_evidence_citations,
)
from app.services.evidence_service import EvidenceService, sanitize_value
from app.services.ollama_client import OllamaClient, is_loopback_host


def test_is_loopback_host_security():
    """Verify SSRF/data exfiltration mitigation: only loopback is permitted."""
    assert is_loopback_host("http://127.0.0.1:11434") is True
    assert is_loopback_host("http://localhost:11434") is True
    assert is_loopback_host("http://[::1]:11434") is True

    # External hosts must be strictly rejected
    assert is_loopback_host("http://192.168.1.50:11434") is False
    assert is_loopback_host("https://api.openai.com/v1") is False
    assert is_loopback_host("http://evil-attacker.com") is False
    assert is_loopback_host("http://10.0.0.1:11434") is False


def test_ollama_client_rejects_external_url():
    """OllamaClient initialization must fail if non-loopback URL is supplied."""
    bad_settings = Settings(OLLAMA_BASE_URL="http://external-server.com:11434")
    with pytest.raises(AppException) as exc_info:
        OllamaClient(settings=bad_settings)
    assert exc_info.value.status_code == 500
    assert "non-loopback" in exc_info.value.message


def test_sanitize_value_redacts_credentials_and_truncates():
    """Verify recursive sanitization: redaction of keys and truncation of oversized strings."""
    data = {
        "user": "analyst",
        "password": "SuperSecretPassword123!",
        "api_key": "sk-secret-key-123",
        "auth_token": "bearer eyJhbGciOi...",
        "normal_text": "A" * 600,
        "nested": {
            "session_id": "sess_9999",
            "safe_val": "ok",
        },
    }
    sanitized = sanitize_value(data)
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["auth_token"] == "[REDACTED]"
    assert sanitized["nested"]["session_id"] == "[REDACTED]"
    assert sanitized["nested"]["safe_val"] == "ok"
    assert sanitized["normal_text"].endswith("... [truncated]")
    assert len(sanitized["normal_text"]) < 550


@pytest.mark.asyncio
async def test_evidence_service_package_construction():
    """Verify EvidenceService builds bounded, sanitized package with EV-01."""
    # Dummy mock opensearch
    class DummyOpenSearch:
        pass

    service = EvidenceService(opensearch=DummyOpenSearch())
    alert = NormalizedAlert(
        alert_id="alert-12345",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc),
        retrieved_at=datetime(2026, 10, 20, 10, 0, 1, tzinfo=timezone.utc),
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=10,
        host_name="web-server-01",
        source_ip="192.168.1.100",
        username="admin",
        raw_evidence_ref="wazuh-alerts-4.x-2026.10.20/alert-12345",
        raw_document={"password": "in-log-password", "srcip": "192.168.1.100"},
    )

    package = await service.build_evidence_package(
        primary_alert=alert,
        package_id="pkg-test-01",
        include_related_events=False,
    )

    assert package.package_id == "pkg-test-01"
    assert package.alert_id == "alert-12345"
    assert package.total_events == 1
    assert len(package.items) == 1
    assert package.items[0].evidence_id == "EV-01"
    assert package.items[0].sanitized_event_data["details"]["password"] == "[REDACTED]"
    assert package.total_bytes > 0


@pytest.mark.asyncio
async def test_ollama_client_offline_handling(monkeypatch):
    """When Ollama is unreachable, client raises 503 DEPENDENCY_UNAVAILABLE."""
    settings = Settings(
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL="llama3.2:3b",
        OLLAMA_TIMEOUT_SECONDS=5,
    )
    client = OllamaClient(settings=settings)

    # Mock _client.post to raise ConnectError
    async def mock_post(*args, **kwargs):
        raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(client._client, "post", mock_post)

    package = EvidencePackage(
        package_id="pkg-1",
        alert_id="alert-1",
        items=[
            EvidenceItem(
                evidence_id="EV-01",
                source_record_id="rec-1",
                event_timestamp=datetime.now(timezone.utc),
                rule_id="5710",
                raw_evidence_ref="wazuh-alerts/1",
            )
        ],
        total_events=1,
        total_bytes=200,
    )

    with pytest.raises(AppException) as exc_info:
        await client.investigate_alert(package, "inv-test")

    assert exc_info.value.status_code == 503
    assert "unavailable" in exc_info.value.message.lower()
    await client.aclose()


@pytest.mark.asyncio
async def test_ollama_client_timeout_handling(monkeypatch):
    """When Ollama times out, client raises 504 UPSTREAM_TIMEOUT."""
    settings = Settings(
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL="llama3.2:3b",
        OLLAMA_TIMEOUT_SECONDS=1,
    )
    client = OllamaClient(settings=settings)

    async def mock_post(*args, **kwargs):
        raise httpx.ReadTimeout("Timeout")

    monkeypatch.setattr(client._client, "post", mock_post)

    package = EvidencePackage(
        package_id="pkg-1",
        alert_id="alert-1",
        items=[
            EvidenceItem(
                evidence_id="EV-01",
                source_record_id="rec-1",
                event_timestamp=datetime.now(timezone.utc),
                rule_id="5710",
                raw_evidence_ref="wazuh-alerts/1",
            )
        ],
        total_events=1,
        total_bytes=200,
    )

    with pytest.raises(AppException) as exc_info:
        await client.investigate_alert(package, "inv-test")

    assert exc_info.value.status_code == 504
    assert "timed out" in exc_info.value.message.lower()
    await client.aclose()


@pytest.mark.asyncio
async def test_ollama_client_missing_model_handling(monkeypatch):
    """When model is not found (404), client raises 404."""
    settings = Settings(
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL="nonexistent-model:latest",
    )
    client = OllamaClient(settings=settings)

    async def mock_post(*args, **kwargs):
        return httpx.Response(status_code=404, text="model not found")

    monkeypatch.setattr(client._client, "post", mock_post)

    package = EvidencePackage(
        package_id="pkg-1",
        alert_id="alert-1",
        items=[
            EvidenceItem(
                evidence_id="EV-01",
                source_record_id="rec-1",
                event_timestamp=datetime.now(timezone.utc),
                rule_id="5710",
                raw_evidence_ref="wazuh-alerts/1",
            )
        ],
        total_events=1,
        total_bytes=200,
    )

    with pytest.raises(AppException) as exc_info:
        await client.investigate_alert(package, "inv-test")

    assert exc_info.value.status_code == 404
    assert "not found" in exc_info.value.message.lower()
    await client.aclose()


@pytest.mark.asyncio
async def test_ollama_client_malformed_json_handling(monkeypatch):
    """When Ollama returns non-JSON content, client raises 502."""
    settings = Settings(
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL="llama3.2:3b",
    )
    client = OllamaClient(settings=settings)

    async def mock_post(*args, **kwargs):
        return httpx.Response(
            status_code=200,
            json={"message": {"role": "assistant", "content": "I am an AI and this is plain text not JSON."}},
        )

    monkeypatch.setattr(client._client, "post", mock_post)

    package = EvidencePackage(
        package_id="pkg-1",
        alert_id="alert-1",
        items=[
            EvidenceItem(
                evidence_id="EV-01",
                source_record_id="rec-1",
                event_timestamp=datetime.now(timezone.utc),
                rule_id="5710",
                raw_evidence_ref="wazuh-alerts/1",
            )
        ],
        total_events=1,
        total_bytes=200,
    )

    with pytest.raises(AppException) as exc_info:
        await client.investigate_alert(package, "inv-test")

    assert exc_info.value.status_code == 502
    assert "not valid structured json" in exc_info.value.message.lower()
    await client.aclose()


@pytest.mark.asyncio
async def test_ollama_client_successful_structured_investigation(monkeypatch):
    """Verify end-to-end parsing of valid structured output and citation cross-validation."""
    settings = Settings(
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL="llama3.2:3b",
    )
    client = OllamaClient(settings=settings)

    valid_response_data = {
        "summary": "SSH brute force attempt detected against invalid username admin.",
        "observed_facts": [
            {
                "fact_id": "F-1",
                "statement": "Failed login attempt from source IP 192.168.1.100.",
                "cited_evidence_ids": ["EV-01"],
            }
        ],
        "hypotheses": [
            {
                "hypothesis_id": "H-1",
                "statement": "Attacker is conducting automated credential spraying.",
                "cited_evidence_ids": ["EV-01"],
                "uncertainty": "medium",
            }
        ],
        "recommended_checks": [
            {
                "check_id": "C-1",
                "description": "Inspect /var/log/auth.log on web-server-01 for other failed attempts.",
                "rationale": "Verify if repeated attempts occurred from same subnet.",
                "priority": "high",
                "is_read_only": True,
            }
        ],
        "limitations": ["No firewall flow logs available."],
        "confidence_label": "high",
    }

    async def mock_post(*args, **kwargs):
        return httpx.Response(
            status_code=200,
            json={"message": {"role": "assistant", "content": json.dumps(valid_response_data)}},
        )

    monkeypatch.setattr(client._client, "post", mock_post)

    package = EvidencePackage(
        package_id="pkg-1",
        alert_id="alert-1",
        items=[
            EvidenceItem(
                evidence_id="EV-01",
                source_record_id="rec-1",
                event_timestamp=datetime.now(timezone.utc),
                rule_id="5710",
                source_ip="192.168.1.100",
                raw_evidence_ref="wazuh-alerts/1",
            ),
            EvidenceItem(
                evidence_id="EV-02",
                source_record_id="rec-2",
                event_timestamp=datetime.now(timezone.utc),
                rule_id="5711",
                source_ip="192.168.1.100",
                raw_evidence_ref="wazuh-alerts/2",
            ),
        ],
        total_events=2,
        total_bytes=400,
    )

    result = await client.investigate_alert(package, "inv-test-123")
    assert result.status == InvestigationStatus.VALID
    assert result.investigation_id == "inv-test-123"
    assert len(result.observed_facts) == 1
    assert result.observed_facts[0].cited_evidence_ids == ["EV-01"]
    assert result.confidence_label == ConfidenceLabel.HIGH
    assert len(result.recommended_checks) == 1
    assert result.recommended_checks[0].is_read_only is True
    # Citation check should have zero warnings because EV-01 exists in package
    assert len(result.unsupported_citation_warnings) == 0

    await client.aclose()


@pytest.mark.asyncio
async def test_ollama_client_flags_hallucinated_evidence_citations(monkeypatch):
    """When model hallucinates non-existent citation (e.g. EV-99), it is caught and warned."""
    settings = Settings(
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL="llama3.2:3b",
    )
    client = OllamaClient(settings=settings)

    hallucinated_data = {
        "summary": "SSH activity analyzed.",
        "observed_facts": [
            {
                "fact_id": "F-1",
                "statement": "Fact citing non-existent event.",
                "cited_evidence_ids": ["EV-99"],  # Does NOT exist in package
            }
        ],
        "hypotheses": [],
        "recommended_checks": [],
        "limitations": [],
        "confidence_label": "low",
    }

    async def mock_post(*args, **kwargs):
        return httpx.Response(
            status_code=200,
            json={"message": {"role": "assistant", "content": json.dumps(hallucinated_data)}},
        )

    monkeypatch.setattr(client._client, "post", mock_post)

    package = EvidencePackage(
        package_id="pkg-1",
        alert_id="alert-1",
        items=[
            EvidenceItem(
                evidence_id="EV-01",
                source_record_id="rec-1",
                event_timestamp=datetime.now(timezone.utc),
                rule_id="5710",
                raw_evidence_ref="wazuh-alerts/1",
            )
        ],
        total_events=1,
        total_bytes=200,
    )

    result = await client.investigate_alert(package, "inv-test-hallucination")
    assert len(result.unsupported_citation_warnings) == 1
    assert "EV-99" in result.unsupported_citation_warnings[0]

    await client.aclose()


@pytest.mark.asyncio
async def test_concurrency_semaphore_limits_parallel_executions():
    """Verify concurrency semaphore blocks when max concurrency is 1."""
    settings = Settings(
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL="llama3.2:3b",
        OLLAMA_MAX_CONCURRENCY=1,
    )
    client = OllamaClient(settings=settings)

    active_executions = 0
    max_observed_concurrency = 0

    async def mock_execute(package, investigation_id, model):
        nonlocal active_executions, max_observed_concurrency
        active_executions += 1
        max_observed_concurrency = max(max_observed_concurrency, active_executions)
        await asyncio.sleep(0.05)
        active_executions -= 1
        return None

    client._execute_inference = mock_execute

    package = EvidencePackage(
        package_id="pkg-1",
        alert_id="alert-1",
        items=[
            EvidenceItem(
                evidence_id="EV-01",
                source_record_id="rec-1",
                event_timestamp=datetime.now(timezone.utc),
                rule_id="5710",
                raw_evidence_ref="wazuh-alerts/1",
            )
        ],
        total_events=1,
        total_bytes=200,
    )

    # Launch 3 concurrent requests
    await asyncio.gather(
        client.investigate_alert(package, "inv-1"),
        client.investigate_alert(package, "inv-2"),
        client.investigate_alert(package, "inv-3"),
    )

    assert max_observed_concurrency == 1
    await client.aclose()
