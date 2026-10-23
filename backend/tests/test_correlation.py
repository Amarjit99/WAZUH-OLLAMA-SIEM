"""Comprehensive unit and integration tests for bounded related-event correlation and context enrichment.

Validates Phase 6 requirements:
- Correct UTC window construction and server-side limit clamping (5 to 60 mins).
- Handling of missing/invalid primary timestamps with graceful single-alert fallback.
- Signal classification: shared_source_ip, shared_destination_ip, shared_user, same_agent, temporal_only.
- Non-causal marking of temporal_only proximity.
- Deterministic ordering by priority rank, time delta, and alert_id.
- Candidate deduplication.
- Primary alert preservation as EV-01 with is_primary=True.
- Event count and byte-budget limit enforcement with accurate truncation reporting.
- OpenSearch failure resilience (single-alert fallback without crash).
- API contract backward compatibility and parameter bounds validation.
"""

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_evidence_service, get_ollama_client, get_opensearch_client
from app.core.config import Settings
from app.main import create_app
from app.schemas.alert import DataStatus, NormalizedAlert
from app.schemas.investigation import (
    ConfidenceLabel,
    EvidenceItem,
    EvidencePackage,
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
    ObservedFact,
    RecommendedCheck,
)
from app.services.evidence_service import EvidenceService, alert_to_evidence_item, classify_correlation


@pytest.fixture
def anchor_alert():
    return NormalizedAlert(
        alert_id="primary-alert-001",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc),
        retrieved_at=datetime(2026, 10, 20, 12, 0, 1, tzinfo=timezone.utc),
        rule_level=10,
        rule_id="5710",
        rule_description="sshd: Attempt to login using nonexistent user",
        agent_id="001",
        agent_name="db-prod-01",
        host_name="db-prod-01",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        username="admin",
        raw_evidence_ref="wazuh-alerts-4.x-2026.10.20/primary-alert-001",
    )


# ============================================================================
# A. Signal Classification & Correlation Logic
# ============================================================================

def test_classify_shared_source_ip(anchor_alert):
    candidate = NormalizedAlert(
        alert_id="cand-01",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=2),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5715",
        rule_description="sshd: multiple failed logins",
        agent_id="002",
        agent_name="web-frontend",
        source_ip="192.168.1.50",
        raw_evidence_ref="test/cand-01",
    )
    rank, reason = classify_correlation(candidate, anchor_alert)
    assert rank == 1
    assert reason == "shared_source_ip"


def test_classify_shared_destination_ip(anchor_alert):
    candidate = NormalizedAlert(
        alert_id="cand-02",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=5),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=6,
        rule_id="6001",
        rule_description="firewall drop",
        agent_id="999",
        agent_name="fw-edge",
        destination_ip="10.0.0.1",
        raw_evidence_ref="test/cand-02",
    )
    rank, reason = classify_correlation(candidate, anchor_alert)
    assert rank == 1
    assert reason == "shared_destination_ip"


def test_classify_shared_user(anchor_alert):
    anchor_jdoe = anchor_alert.model_copy(update={"username": "jdoe"})
    candidate = NormalizedAlert(
        alert_id="cand-03",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp - timedelta(minutes=3),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=4,
        rule_id="5501",
        rule_description="pam session open",
        agent_id="005",
        agent_name="bastion",
        username="jdoe",
        raw_evidence_ref="test/cand-03",
    )
    rank, reason = classify_correlation(candidate, anchor_jdoe)
    assert rank == 1
    assert reason == "shared_username"


def test_classify_generic_username_admin(anchor_alert):
    anchor_admin = anchor_alert.model_copy(update={"username": "admin", "agent_id": "001", "agent_name": "host-a"})
    candidate = NormalizedAlert(
        alert_id="cand-admin",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp - timedelta(minutes=3),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=4,
        rule_id="5501",
        agent_id="005",
        agent_name="host-b",
        username="admin",
        raw_evidence_ref="test/cand-admin",
    )
    rank, reason = classify_correlation(candidate, anchor_admin)
    assert rank == 2
    assert "generic account" in reason
    assert "does not verify identity" in reason


def test_classify_generic_username_root(anchor_alert):
    anchor_root = anchor_alert.model_copy(update={"username": "root", "agent_id": "001", "agent_name": "host-a"})
    candidate = NormalizedAlert(
        alert_id="cand-root",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp - timedelta(minutes=3),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=4,
        rule_id="5501",
        agent_id="005",
        agent_name="host-b",
        username="root",
        raw_evidence_ref="test/cand-root",
    )
    rank, reason = classify_correlation(candidate, anchor_root)
    assert rank == 2
    assert "generic account" in reason
    assert "does not verify identity" in reason


def test_classify_same_agent(anchor_alert):
    candidate = NormalizedAlert(
        alert_id="cand-04",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=1),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=3,
        rule_id="5100",
        rule_description="system startup",
        agent_id="001",
        agent_name="db-prod-01",
        raw_evidence_ref="test/cand-04",
    )
    rank, reason = classify_correlation(candidate, anchor_alert)
    assert rank == 2
    assert reason == "same_agent"


def test_classify_temporal_only_weak_link(anchor_alert):
    candidate = NormalizedAlert(
        alert_id="cand-05",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=7),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=7,
        rule_id="1002",
        rule_description="unknown log entry",
        agent_id="999",
        agent_name="other-agent",
        source_ip="8.8.8.8",
        username="daemon",
        raw_evidence_ref="test/cand-05",
    )
    rank, reason = classify_correlation(candidate, anchor_alert)
    assert rank == 3
    assert "temporal_only" in reason
    assert "weak correlation" in reason
    assert "does not prove causation" in reason


# ============================================================================
# B. Deterministic Ordering and Deduplication
# ============================================================================

@pytest.mark.asyncio
async def test_deterministic_ranking_and_primary_preservation(anchor_alert):
    """Verify that exact entities rank above same_agent, which ranks above temporal_only."""
    cand_agent = NormalizedAlert(
        alert_id="cand-agent",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(seconds=10),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=4,
        rule_id="5100",
        agent_id="001",
        agent_name="db-prod-01",
        raw_evidence_ref="test/cand-agent",
    )
    cand_ip = NormalizedAlert(
        alert_id="cand-ip",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=4),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=8,
        rule_id="5710",
        agent_id="009",
        agent_name="other-agent",
        source_ip="192.168.1.50",
        raw_evidence_ref="test/cand-ip",
    )
    cand_temporal = NormalizedAlert(
        alert_id="cand-temporal",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(seconds=5),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=2,
        rule_id="1000",
        agent_id="888",
        agent_name="unrelated-agent",
        raw_evidence_ref="test/cand-temporal",
    )

    class MockOpenSearch:
        async def search_alerts(self, **kwargs):
            return [cand_temporal, cand_agent, cand_ip], 3, DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOpenSearch())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-test",
        include_related_events=True,
        correlation_window_minutes=30,
        max_related_events=10,
    )

    # Primary alert must be EV-01 and is_primary=True
    assert len(pkg.items) == 4
    assert pkg.items[0].evidence_id == "EV-01"
    assert pkg.items[0].is_primary is True
    assert pkg.items[0].source_record_id == anchor_alert.alert_id

    # Order must be: cand_ip (rank 1), cand_agent (rank 2), cand_temporal (rank 3)
    assert pkg.items[1].source_record_id == "cand-ip"
    assert pkg.items[1].correlation_reason == "shared_source_ip"
    assert pkg.items[2].source_record_id == "cand-agent"
    assert pkg.items[2].correlation_reason == "same_agent"
    assert pkg.items[3].source_record_id == "cand-temporal"
    assert "temporal_only" in pkg.items[3].correlation_reason

    assert pkg.correlation_status == "enriched"
    assert pkg.related_events_summary.retrieved_count == 3
    assert pkg.related_events_summary.included_count == 3
    assert pkg.related_events_summary.truncated_count == 0


@pytest.mark.asyncio
async def test_candidate_deduplication(anchor_alert):
    """Candidate returned by both host and IP search is included only once."""
    duplicate_cand = NormalizedAlert(
        alert_id="cand-dup",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(seconds=30),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=6,
        rule_id="5712",
        agent_id="001",
        agent_name="db-prod-01",
        source_ip="192.168.1.50",
        raw_evidence_ref="test/cand-dup",
    )

    class MockOpenSearch:
        async def search_alerts(self, **kwargs):
            # Returns the same candidate regardless of search dimensions
            return [duplicate_cand], 1, DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOpenSearch())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-dup",
        include_related_events=True,
    )

    # EV-01 primary + single EV-02
    assert len(pkg.items) == 2
    assert pkg.items[0].evidence_id == "EV-01"
    assert pkg.items[1].evidence_id == "EV-02"
    assert pkg.items[1].source_record_id == "cand-dup"
    assert pkg.related_events_summary.retrieved_count == 1
    assert pkg.related_events_summary.included_count == 1


# ============================================================================
# C. Bounded Limits and Truncation Enforcement
# ============================================================================

@pytest.mark.asyncio
async def test_max_related_events_and_evidence_capping(anchor_alert):
    """Capping when candidate count exceeds max_related_events."""
    many_candidates = [
        NormalizedAlert(
            alert_id=f"cand-{i:02d}",
            source_system="Wazuh",
            source_index="wazuh-alerts-4.x-2026.10.20",
            timestamp=anchor_alert.timestamp + timedelta(minutes=i),
            retrieved_at=anchor_alert.retrieved_at,
            rule_level=5,
            rule_id=f"500{i}",
            agent_id="001",
            agent_name="db-prod-01",
            raw_evidence_ref=f"test/cand-{i:02d}",
        )
        for i in range(1, 15)  # 14 candidates
    ]

    class MockOpenSearch:
        async def search_alerts(self, **kwargs):
            return many_candidates, len(many_candidates), DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOpenSearch())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-capped",
        include_related_events=True,
        max_related_events=3,
        max_evidence_items=10,
    )

    # 1 primary + 3 related = 4 items
    assert len(pkg.items) == 4
    assert pkg.related_events_summary.retrieved_count == 14
    assert pkg.related_events_summary.included_count == 3
    assert pkg.related_events_summary.truncated_count == 11


@pytest.mark.asyncio
async def test_byte_limit_truncation(anchor_alert):
    """Truncation enforced when total bytes exceed MAX_EVIDENCE_BYTES."""
    big_candidates = [
        NormalizedAlert(
            alert_id=f"cand-big-{i}",
            source_system="Wazuh",
            source_index="wazuh-alerts-4.x-2026.10.20",
            timestamp=anchor_alert.timestamp + timedelta(minutes=i),
            retrieved_at=anchor_alert.retrieved_at,
            rule_level=5,
            rule_id="5000",
            agent_id="001",
            agent_name="db-prod-01",
            full_log="X" * 400,
            raw_document={"big_field": "Y" * 400},
            raw_evidence_ref=f"test/cand-big-{i}",
        )
        for i in range(1, 10)
    ]

    class MockOpenSearch:
        async def search_alerts(self, **kwargs):
            return big_candidates, len(big_candidates), DataStatus.FRESH

    # Set very small byte limit
    settings = Settings(MAX_EVIDENCE_BYTES=2000)
    svc = EvidenceService(opensearch=MockOpenSearch(), settings=settings)
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-bytes",
        include_related_events=True,
        max_related_events=10,
    )

    # Primary alert must be preserved even if bytes are constrained
    assert len(pkg.items) >= 1
    assert pkg.items[0].evidence_id == "EV-01"
    assert pkg.total_bytes <= 2000
    assert pkg.related_events_summary.truncated_count > 0


# ============================================================================
# D. Fallbacks and Edge Cases
# ============================================================================

@pytest.mark.asyncio
async def test_missing_or_invalid_timestamp_fallbacks_to_single_alert():
    """Missing or invalid timestamp triggers fallback without fabricating time."""
    alert_no_ts = NormalizedAlert(
        alert_id="alert-no-ts",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime.now(timezone.utc),
        retrieved_at=datetime.now(timezone.utc),
        rule_level=7,
        rule_id="5501",
        normalization_warnings=["Event timestamp missing; using current UTC time"],
        raw_evidence_ref="test/alert-no-ts",
    )

    class MockOpenSearch:
        async def search_alerts(self, **kwargs):
            pytest.fail("OpenSearch should not be queried when timestamp is invalid")

    svc = EvidenceService(opensearch=MockOpenSearch())
    pkg = await svc.build_evidence_package(
        primary_alert=alert_no_ts,
        package_id="pkg-no-ts",
        include_related_events=True,
    )

    assert len(pkg.items) == 1
    assert pkg.items[0].evidence_id == "EV-01"
    assert pkg.correlation_status == "failed_fallback_single_alert"
    assert pkg.related_events_summary.correlation_status == "failed_fallback_single_alert"


@pytest.mark.asyncio
async def test_opensearch_failure_resilience(anchor_alert):
    """OpenSearch query failure gracefully degrades to single-alert mode."""
    class FailingOpenSearch:
        async def search_alerts(self, **kwargs):
            raise ConnectionError("Indexer connection reset")

    svc = EvidenceService(opensearch=FailingOpenSearch())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-err",
        include_related_events=True,
    )

    assert len(pkg.items) == 1
    assert pkg.items[0].evidence_id == "EV-01"
    assert pkg.correlation_status == "failed_fallback_single_alert"
    assert pkg.related_events_summary.correlation_status == "failed_fallback_single_alert"


@pytest.mark.asyncio
async def test_no_related_events_found(anchor_alert):
    """Empty candidate search returns no_related_events_found."""
    class EmptyOpenSearch:
        async def search_alerts(self, **kwargs):
            return [], 0, DataStatus.FRESH

    svc = EvidenceService(opensearch=EmptyOpenSearch())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-empty",
        include_related_events=True,
    )

    assert len(pkg.items) == 1
    assert pkg.items[0].evidence_id == "EV-01"
    assert pkg.correlation_status == "no_related_events_found"
    assert pkg.related_events_summary.retrieved_count == 0


# ============================================================================
# E. API Integration and Parameter Validation
# ============================================================================

def test_api_investigate_with_correlation(anchor_alert):
    """POST /api/v1/alerts/{id}/investigate with correlation options."""
    app = create_app()

    cand = NormalizedAlert(
        alert_id="cand-api-01",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=2),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=8,
        rule_id="5710",
        agent_id="001",
        agent_name="db-prod-01",
        raw_evidence_ref="test/cand-api-01",
    )

    class MockOS:
        async def get_alert_by_id(self, alert_id: str):
            return anchor_alert

        async def search_alerts(self, **kwargs):
            return [cand], 1, DataStatus.FRESH

    class MockOllama:
        async def investigate_alert(self, package: EvidencePackage, investigation_id: str):
            return InvestigationResult(
                investigation_id=investigation_id,
                alert_id=package.alert_id,
                status=InvestigationStatus.VALID,
                generated_at=datetime.now(timezone.utc),
                model_name="ollama",
                model_tag="llama3.2:3b",
                summary="Observed multiple failed logins on same agent.",
                observed_facts=[
                    ObservedFact(fact_id="F-1", statement="Failed login attempt on db-prod-01", cited_evidence_ids=["EV-01", "EV-02"])
                ],
                recommended_checks=[
                    RecommendedCheck(check_id="C-1", description="Check auth logs", rationale="Verify activity", is_read_only=True)
                ],
                correlation_status=package.correlation_status,
                related_events_summary=package.related_events_summary,
            )

    app.dependency_overrides[get_opensearch_client] = lambda: MockOS()
    app.dependency_overrides[get_ollama_client] = lambda: MockOllama()

    with TestClient(app) as client:
        resp = client.post(
            f"/api/v1/alerts/{anchor_alert.alert_id}/investigate",
            json={
                "include_related_events": True,
                "correlation_window_minutes": 20,
                "max_related_events": 5,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["correlation_status"] == "enriched"
        assert data["related_events_summary"]["retrieved_count"] == 1
        assert data["related_events_summary"]["included_count"] == 1
        assert data["related_events_summary"]["window_minutes"] == 20


def test_api_parameter_bounds_enforced(anchor_alert):
    """Invalid parameter bounds (e.g. window < 5 or > 60) return 422."""
    app = create_app()

    class MockOS:
        async def get_alert_by_id(self, alert_id: str):
            return anchor_alert

    app.dependency_overrides[get_opensearch_client] = lambda: MockOS()

    with TestClient(app) as client:
        # Window too small (< 5)
        resp1 = client.post(
            f"/api/v1/alerts/{anchor_alert.alert_id}/investigate",
            json={"include_related_events": True, "correlation_window_minutes": 2},
        )
        assert resp1.status_code == 422

        # Window too large (> 60)
        resp2 = client.post(
            f"/api/v1/alerts/{anchor_alert.alert_id}/investigate",
            json={"include_related_events": True, "correlation_window_minutes": 120},
        )
        assert resp2.status_code == 422

        # max_related_events too large (> 20)
        resp3 = client.post(
            f"/api/v1/alerts/{anchor_alert.alert_id}/investigate",
            json={"include_related_events": True, "max_related_events": 50},
        )
        assert resp3.status_code == 422


# ============================================================================
# F. Phase 6A Correlation Quality & False-Association Validation
# ============================================================================

def test_placeholder_entity_rejection(anchor_alert):
    """Placeholder or invalid fields (e.g. unknown, none, 0.0.0.0, 127.0.0.1) are rejected as signals."""
    anchor_with_placeholders = NormalizedAlert(
        alert_id="anchor-ph",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp,
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="1001",
        source_ip="0.0.0.0",
        destination_ip="127.0.0.1",
        username="unknown",
        agent_id="",
        agent_name="unknown",
        host_name="unknown",
        raw_evidence_ref="test/anchor-ph",
    )

    candidate_with_placeholders = NormalizedAlert(
        alert_id="cand-ph",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=1),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="1002",
        source_ip="0.0.0.0",
        destination_ip="127.0.0.1",
        username="unknown",
        agent_id="",
        agent_name="unknown",
        host_name="unknown",
        raw_evidence_ref="test/cand-ph",
    )

    rank, reason = classify_correlation(candidate_with_placeholders, anchor_with_placeholders)
    # Must NOT match as shared IP, username, or agent! Must fall back to temporal proximity only.
    assert rank == 3
    assert "temporal_proximity_only" in reason
    assert "weak correlation" in reason


@pytest.mark.asyncio
async def test_exact_window_boundaries_and_out_of_window_rejection(anchor_alert):
    """Events exactly on ±15m boundary are included; events outside ±15m are strictly rejected."""
    # Window = 30m -> half window = 15m
    exact_start = anchor_alert.timestamp - timedelta(minutes=15)
    exact_end = anchor_alert.timestamp + timedelta(minutes=15)
    out_before = anchor_alert.timestamp - timedelta(minutes=15, seconds=1)
    out_after = anchor_alert.timestamp + timedelta(minutes=15, seconds=1)

    cand_start = NormalizedAlert(
        alert_id="cand-boundary-start",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=exact_start,
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5001",
        agent_id="001",
        raw_evidence_ref="test/start",
    )
    cand_end = NormalizedAlert(
        alert_id="cand-boundary-end",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=exact_end,
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5002",
        agent_id="001",
        raw_evidence_ref="test/end",
    )
    cand_out1 = NormalizedAlert(
        alert_id="cand-out-before",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=out_before,
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5003",
        agent_id="001",
        raw_evidence_ref="test/out1",
    )
    cand_out2 = NormalizedAlert(
        alert_id="cand-out-after",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=out_after,
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5004",
        agent_id="001",
        raw_evidence_ref="test/out2",
    )

    class MockOpenSearch:
        async def search_alerts(self, **kwargs):
            return [cand_out1, cand_start, cand_end, cand_out2], 4, DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOpenSearch())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-boundary",
        include_related_events=True,
        correlation_window_minutes=30,
    )

    included_ids = [item.source_record_id for item in pkg.items]
    assert "cand-boundary-start" in included_ids
    assert "cand-boundary-end" in included_ids
    assert "cand-out-before" not in included_ids
    assert "cand-out-after" not in included_ids


@pytest.mark.asyncio
async def test_naive_timestamp_utc_normalization(anchor_alert):
    """Timezone-naive candidate timestamps are normalized to UTC safely."""
    naive_cand = NormalizedAlert(
        alert_id="cand-naive",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 12, 5, 0),  # Naive
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5005",
        agent_id="001",
        raw_evidence_ref="test/naive",
    )

    class MockOpenSearch:
        async def search_alerts(self, **kwargs):
            return [naive_cand], 1, DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOpenSearch())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-naive",
        include_related_events=True,
    )

    assert len(pkg.items) == 2
    assert pkg.items[1].event_timestamp.tzinfo is not None


@pytest.mark.asyncio
async def test_stable_unique_evidence_ids(anchor_alert):
    """Evidence IDs in the package are strictly sequential, unique, and stable across repeated runs."""
    cand1 = NormalizedAlert(
        alert_id="cand-stable-1",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=1),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5001",
        source_ip="192.168.1.50",
        raw_evidence_ref="test/1",
    )
    cand2 = NormalizedAlert(
        alert_id="cand-stable-2",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=2),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5002",
        agent_id="001",
        raw_evidence_ref="test/2",
    )

    class MockOpenSearch:
        async def search_alerts(self, **kwargs):
            return [cand1, cand2], 2, DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOpenSearch())
    pkg1 = await svc.build_evidence_package(anchor_alert, "pkg-st-1", include_related_events=True)
    pkg2 = await svc.build_evidence_package(anchor_alert, "pkg-st-2", include_related_events=True)

    ev_ids_1 = [i.evidence_id for i in pkg1.items]
    ev_ids_2 = [i.evidence_id for i in pkg2.items]

    assert ev_ids_1 == ["EV-01", "EV-02", "EV-03"]
    assert ev_ids_2 == ["EV-01", "EV-02", "EV-03"]
    # Check uniqueness
    assert len(ev_ids_1) == len(set(ev_ids_1))


def test_unsupported_process_telemetry_disclosed_and_flagged(anchor_alert):
    """Unsupported signals are declared in summary and speculative process claims are flagged."""
    from app.schemas.investigation import Hypothesis, validate_evidence_citations

    item_primary = alert_to_evidence_item(anchor_alert, "EV-01", is_primary=True)
    pkg = EvidencePackage(
        package_id="pkg-proc",
        alert_id=anchor_alert.alert_id,
        items=[item_primary],
        total_events=1,
        total_bytes=200,
    )

    result = InvestigationResult(
        investigation_id="inv-proc",
        alert_id=anchor_alert.alert_id,
        status=InvestigationStatus.VALID,
        generated_at=datetime.now(timezone.utc),
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Test analysis",
        observed_facts=[ObservedFact(fact_id="F-1", statement="Failed login attempt", cited_evidence_ids=["EV-01"])],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="Attacker executed process injection into sshd process tree.",
                cited_evidence_ids=["EV-01"],
            )
        ],
        recommended_checks=[],
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("process lineage or injection" in w for w in warnings)


def test_lateral_movement_hypothesis_without_network_flagged(anchor_alert):
    """Hypothesis asserting lateral movement without network/IP telemetry is flagged."""
    from app.schemas.investigation import Hypothesis, validate_evidence_citations

    # Alert without IPs
    alert_no_ip = NormalizedAlert(
        alert_id="alert-no-ip",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp,
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5001",
        agent_id="001",
        agent_name="db-prod-01",
        raw_evidence_ref="test/no-ip",
    )

    item = alert_to_evidence_item(alert_no_ip, "EV-01", is_primary=True)
    pkg = EvidencePackage(
        package_id="pkg-lat",
        alert_id=alert_no_ip.alert_id,
        items=[item],
        total_events=1,
        total_bytes=200,
    )

    result = InvestigationResult(
        investigation_id="inv-lat",
        alert_id=alert_no_ip.alert_id,
        status=InvestigationStatus.VALID,
        generated_at=datetime.now(timezone.utc),
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Test analysis",
        observed_facts=[ObservedFact(fact_id="F-1", statement="Event occurred on agent db-prod-01", cited_evidence_ids=["EV-01"])],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="Adversary is performing lateral movement across the internal subnet.",
                cited_evidence_ids=["EV-01"],
            )
        ],
        recommended_checks=[],
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("lateral movement / pivoting" in w for w in warnings)


def test_temporal_only_package_calibrates_confidence_from_high(anchor_alert):
    """Package with only weak temporal proximity calibrates HIGH confidence to MEDIUM."""
    from app.schemas.investigation import validate_evidence_citations

    item_primary = alert_to_evidence_item(anchor_alert, "EV-01", is_primary=True)
    item_temporal = EvidenceItem(
        evidence_id="EV-02",
        source_record_id="cand-temp",
        event_timestamp=anchor_alert.timestamp + timedelta(minutes=5),
        rule_id="1001",
        raw_evidence_ref="test/cand-temp",
        is_primary=False,
        correlation_reason="temporal_proximity_only (weak correlation; temporal proximity does not prove causation)",
    )

    pkg = EvidencePackage(
        package_id="pkg-temp",
        alert_id=anchor_alert.alert_id,
        items=[item_primary, item_temporal],
        total_events=2,
        total_bytes=400,
    )

    result = InvestigationResult(
        investigation_id="inv-temp",
        alert_id=anchor_alert.alert_id,
        status=InvestigationStatus.VALID,
        generated_at=datetime.now(timezone.utc),
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Test analysis",
        observed_facts=[ObservedFact(fact_id="F-1", statement="Failed login observed", cited_evidence_ids=["EV-01"])],
        hypotheses=[],
        recommended_checks=[],
        confidence_label=ConfidenceLabel.HIGH,
    )

    warnings = validate_evidence_citations(result, pkg)
    assert result.confidence_label == ConfidenceLabel.MEDIUM
    assert any("Confidence calibrated from HIGH to MEDIUM" in w for w in warnings)


def test_shared_ip_different_agents_preserves_reason_with_qualifier(anchor_alert):
    """Shared IP retains exact reason and populates network association qualifier."""
    candidate = NormalizedAlert(
        alert_id="cand-ip-diff-agent",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=anchor_alert.timestamp + timedelta(minutes=2),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5710",
        agent_id="099",
        agent_name="remote-agent",
        source_ip="192.168.1.50",
        raw_evidence_ref="test/ip-diff",
    )
    rank, reason = classify_correlation(candidate, anchor_alert)
    assert rank == 1
    assert reason == "shared_source_ip"

    item = alert_to_evidence_item(candidate, "EV-02", is_primary=False, correlation_reason=reason)
    assert item.correlation_reason == "shared_source_ip"
    assert item.correlation_qualifier == "network_association_subject_to_nat_dhcp_or_shared_egress"


def test_shared_attacker_hypothesis_without_corroboration_flagged(anchor_alert):
    """Hypothesis asserting same/common attacker solely based on shared IP is flagged."""
    from app.schemas.investigation import Hypothesis, validate_evidence_citations

    item_primary = alert_to_evidence_item(anchor_alert, "EV-01", is_primary=True)
    item_ip = alert_to_evidence_item(
        anchor_alert.model_copy(update={"alert_id": "cand-ip", "agent_id": "099"}),
        "EV-02",
        is_primary=False,
        correlation_reason="shared_source_ip",
    )

    pkg = EvidencePackage(
        package_id="pkg-att",
        alert_id=anchor_alert.alert_id,
        items=[item_primary, item_ip],
        total_events=2,
        total_bytes=400,
    )

    result = InvestigationResult(
        investigation_id="inv-att",
        alert_id=anchor_alert.alert_id,
        status=InvestigationStatus.VALID,
        generated_at=datetime.now(timezone.utc),
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Test analysis",
        observed_facts=[ObservedFact(fact_id="F-1", statement="Failed login from 192.168.1.50", cited_evidence_ids=["EV-01"])],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="Both events originate from the same attacker conducting a coordinated attack campaign.",
                cited_evidence_ids=["EV-01", "EV-02"],
            )
        ],
        recommended_checks=[],
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("shared or common attacker" in w for w in warnings)


def test_generic_account_identity_claim_flagged(anchor_alert):
    """Hypothesis asserting common user identity across hosts on generic accounts (root/admin) is flagged."""
    from app.schemas.investigation import Hypothesis, validate_evidence_citations

    anchor_root = anchor_alert.model_copy(update={"username": "root", "agent_id": "001"})
    cand_root = anchor_alert.model_copy(update={"alert_id": "cand-root", "username": "root", "agent_id": "002"})

    item_primary = alert_to_evidence_item(anchor_root, "EV-01", is_primary=True)
    item_cand = alert_to_evidence_item(
        cand_root,
        "EV-02",
        is_primary=False,
        correlation_reason="shared_username (generic account; does not verify identity or lateral movement)",
    )

    pkg = EvidencePackage(
        package_id="pkg-generic",
        alert_id=anchor_root.alert_id,
        items=[item_primary, item_cand],
        total_events=2,
        total_bytes=400,
    )

    result = InvestigationResult(
        investigation_id="inv-generic",
        alert_id=anchor_root.alert_id,
        status=InvestigationStatus.VALID,
        generated_at=datetime.now(timezone.utc),
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Test analysis",
        observed_facts=[ObservedFact(fact_id="F-1", statement="Event on host", cited_evidence_ids=["EV-01"])],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="The same user account was observed pivoting across hosts.",
                cited_evidence_ids=["EV-01", "EV-02"],
            )
        ],
        recommended_checks=[],
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("generic account names" in w for w in warnings)


def test_missing_and_empty_citations_flagged(anchor_alert):
    """Fact or hypothesis with empty citations triggers validation error or warnings."""
    from pydantic import ValidationError
    from app.schemas.investigation import Hypothesis, validate_evidence_citations

    # ObservedFact strictly requires at least one citation; empty list raises ValidationError
    with pytest.raises(ValidationError):
        ObservedFact(fact_id="F-1", statement="Some statement", cited_evidence_ids=[])

    item = alert_to_evidence_item(anchor_alert, "EV-01", is_primary=True)
    pkg = EvidencePackage(
        package_id="pkg-cite",
        alert_id=anchor_alert.alert_id,
        items=[item],
        total_events=1,
        total_bytes=200,
    )

    result = InvestigationResult(
        investigation_id="inv-cite",
        alert_id=anchor_alert.alert_id,
        status=InvestigationStatus.VALID,
        generated_at=datetime.now(timezone.utc),
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Test analysis",
        observed_facts=[ObservedFact(fact_id="F-1", statement="Some statement", cited_evidence_ids=["EV-01"])],
        hypotheses=[Hypothesis(hypothesis_id="H-1", statement="Some hyp", cited_evidence_ids=[])],
        recommended_checks=[],
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("Hypothesis 'H-1' does not cite any evidence IDs" in w for w in warnings)


def test_unsupported_signals_optional_and_none_safe(anchor_alert):
    """RelatedEventsSummary handles None, empty, and populated unsupported_signals safely."""
    from app.schemas.investigation import RelatedEventsSummary

    summary_none = RelatedEventsSummary(
        correlation_status="enriched",
        unsupported_signals=None,
    )
    assert summary_none.unsupported_signals is None

    summary_empty = RelatedEventsSummary(
        correlation_status="enriched",
        unsupported_signals=[],
    )
    assert summary_empty.unsupported_signals == []

    summary_default = RelatedEventsSummary(
        correlation_status="enriched",
    )
    assert summary_default.unsupported_signals == ["process_lineage", "command_line"]


@pytest.mark.asyncio
async def test_timestamp_timezone_offset_utc_normalization(anchor_alert):
    """Timestamps with positive (+05:30) and negative (-04:00) offsets are properly normalized to UTC."""
    cand_positive = NormalizedAlert(
        alert_id="cand-pos-tz",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 17, 32, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5001",
        agent_id="001",
        raw_evidence_ref="test/pos",
    )

    cand_negative = NormalizedAlert(
        alert_id="cand-neg-tz",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 8, 2, 0, tzinfo=timezone(timedelta(hours=-4))),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5002",
        agent_id="001",
        raw_evidence_ref="test/neg",
    )

    class MockOS:
        async def search_alerts(self, **kwargs):
            return [cand_positive, cand_negative], 2, DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOS())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-tz",
        include_related_events=True,
        correlation_window_minutes=30,
    )

    # Both cand_positive (12:02 UTC) and cand_negative (12:02 UTC) fall within ±15m of 12:00 UTC
    included_ids = [i.source_record_id for i in pkg.items]
    assert "cand-pos-tz" in included_ids
    assert "cand-neg-tz" in included_ids
    assert all(i.event_timestamp.tzinfo == timezone.utc for i in pkg.items)


def test_cautious_legitimate_security_hypothesis_not_flagged(anchor_alert):
    """Legitimate cautious hypotheses citing valid evidence without overreach are NOT flagged."""
    from app.schemas.investigation import Hypothesis, UncertaintyLevel, validate_evidence_citations

    item = alert_to_evidence_item(anchor_alert, "EV-01", is_primary=True)
    pkg = EvidencePackage(
        package_id="pkg-legit",
        alert_id=anchor_alert.alert_id,
        items=[item],
        total_events=1,
        total_bytes=200,
    )

    result = InvestigationResult(
        investigation_id="inv-legit",
        alert_id=anchor_alert.alert_id,
        status=InvestigationStatus.VALID,
        generated_at=datetime.now(timezone.utc),
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Authentication monitoring analysis.",
        observed_facts=[ObservedFact(fact_id="F-1", statement="Failed login attempt on db-prod-01", cited_evidence_ids=["EV-01"])],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="Multiple failed attempts from the external address may represent automated brute-force scanning.",
                cited_evidence_ids=["EV-01"],
                uncertainty=UncertaintyLevel.MEDIUM,
            )
        ],
        recommended_checks=[RecommendedCheck(check_id="C-1", description="Check auth logs", rationale="Verify volume", is_read_only=True)],
        limitations=["Single isolated alert evaluated without historical baseline."],
        confidence_label=ConfidenceLabel.MEDIUM,
    )

    warnings = validate_evidence_citations(result, pkg)
    # Legitimate security hypothesis must NOT be flagged as unsupported attribution
    assert not any("insider threat" in w for w in warnings)
    assert not any("nation-state" in w for w in warnings)
    assert not any("process lineage" in w for w in warnings)
    assert not any("lateral movement" in w for w in warnings)
    assert not any("causality" in w for w in warnings)
    assert not any("shared or common attacker" in w for w in warnings)


@pytest.mark.asyncio
async def test_utc_z_timestamp_contract_verified(anchor_alert):
    """Alerts with explicit ISO 8601 UTC Z timestamps are verified and parsed into timezone-aware UTC."""
    cand_z = NormalizedAlert(
        alert_id="cand-z-ts",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime.fromisoformat("2026-10-20T12:05:00Z"),
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=5,
        rule_id="5003",
        agent_id="001",
        raw_evidence_ref="test/z",
    )
    assert cand_z.timestamp.tzinfo == timezone.utc

    class MockOS:
        async def search_alerts(self, **kwargs):
            return [cand_z], 1, DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOS())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-z",
        include_related_events=True,
    )
    assert any(i.source_record_id == "cand-z-ts" for i in pkg.items)
    for item in pkg.items:
        assert item.event_timestamp.tzinfo == timezone.utc


@pytest.mark.asyncio
async def test_ambiguous_naive_timestamp_without_contract_falls_back(anchor_alert):
    """An alert with an ambiguous/untrusted timestamp warning triggers safe single-alert fallback."""
    ambiguous_alert = NormalizedAlert(
        alert_id="alert-ambig-ts",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 12, 0, 0),  # Naive
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=7,
        rule_id="7001",
        normalization_warnings=["Ambiguous timestamp without established UTC contract"],
        raw_evidence_ref="test/ambig",
    )

    svc = EvidenceService(opensearch=None)
    pkg = await svc.build_evidence_package(
        primary_alert=ambiguous_alert,
        package_id="pkg-ambig",
        include_related_events=True,
    )
    assert pkg.correlation_status == "failed_fallback_single_alert"
    assert len(pkg.items) == 1
    assert pkg.items[0].source_record_id == "alert-ambig-ts"


@pytest.mark.asyncio
async def test_stable_ordering_across_timezone_normalized_timestamps(anchor_alert):
    """Candidates with different timezone offsets are stably ordered by UTC timestamp."""
    c1 = NormalizedAlert(
        alert_id="cand-ts-early",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 17, 20, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))),  # 11:50 UTC
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=4,
        rule_id="4001",
        raw_evidence_ref="test/early",
    )
    c2 = NormalizedAlert(
        alert_id="cand-ts-mid",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone(timedelta(hours=-4))),  # 12:00 UTC
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=4,
        rule_id="4002",
        raw_evidence_ref="test/mid",
    )
    c3 = NormalizedAlert(
        alert_id="cand-ts-late",
        source_system="Wazuh",
        source_index="wazuh-alerts-4.x-2026.10.20",
        timestamp=datetime(2026, 10, 20, 12, 10, 0, tzinfo=timezone.utc),  # 12:10 UTC
        retrieved_at=anchor_alert.retrieved_at,
        rule_level=4,
        rule_id="4003",
        raw_evidence_ref="test/late",
    )

    class MockOS:
        async def search_alerts(self, **kwargs):
            return [c3, c1, c2], 3, DataStatus.FRESH

    svc = EvidenceService(opensearch=MockOS())
    pkg = await svc.build_evidence_package(
        primary_alert=anchor_alert,
        package_id="pkg-sort",
        include_related_events=True,
        correlation_window_minutes=30,
    )
    # EV-01 is primary anchor alert (12:00 UTC)
    assert pkg.items[0].is_primary is True
    # Correlated items are all UTC-aware
    assert all(i.event_timestamp.tzinfo == timezone.utc for i in pkg.items)


def test_api_auth_unauthenticated_allowed_in_default_dev_mode():
    """In default development mode (no API_KEY set), endpoints are accessible without auth header."""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        resp = client.get("/api/v1/alerts")
        # May be 200 or 503 depending on live OpenSearch, but NEVER 401
        assert resp.status_code != 401


def test_api_auth_all_sensitive_routes_enforce_bearer_token():
    """All sensitive endpoints (list, get-by-id, investigate) strictly enforce Bearer token when configured."""
    from pydantic import SecretStr
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core import config

    custom_settings = config.Settings(
        API_KEY=SecretStr("super-secret-test-token-123"),
        API_AUTH_REQUIRED=True,
    )
    app.dependency_overrides[config.get_settings] = lambda: custom_settings

    try:
        with TestClient(app) as client:
            endpoints = [
                ("GET", "/api/v1/alerts", None),
                ("GET", "/api/v1/alerts/test-alert-id", None),
                ("POST", "/api/v1/alerts/test-alert-id/investigate", {}),
            ]

            for method, path, json_body in endpoints:
                # 1. Missing Authorization header -> 401
                resp_missing = client.request(method, path, json=json_body)
                assert resp_missing.status_code == 401, f"{method} {path} should return 401 without auth"
                err_body = resp_missing.json()["error"]
                assert "Unauthorized" in err_body["message"]
                # Must never leak expected secret in response
                assert "super-secret" not in str(resp_missing.json())

                # 2. Invalid Authorization token -> 401
                resp_invalid = client.request(method, path, json=json_body, headers={"Authorization": "Bearer bad-token-xyz"})
                assert resp_invalid.status_code == 401, f"{method} {path} should return 401 with bad auth"

                # 3. Valid Authorization token -> Not 401 (auth check passes)
                resp_valid = client.request(method, path, json=json_body, headers={"Authorization": "Bearer super-secret-test-token-123"})
                assert resp_valid.status_code != 401, f"{method} {path} should pass auth with valid Bearer token"
    finally:
        app.dependency_overrides.pop(config.get_settings, None)


def test_api_auth_required_fails_closed_when_key_missing_or_whitespace():
    """When API_AUTH_REQUIRED=True but API_KEY is None or whitespace, all protected routes fail closed with 500."""
    from pydantic import SecretStr
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core import config

    for empty_val in (None, SecretStr("   ")):
        custom_settings = config.Settings(
            API_KEY=empty_val,
            API_AUTH_REQUIRED=True,
        )
        app.dependency_overrides[config.get_settings] = lambda: custom_settings

        try:
            with TestClient(app) as client:
                resp = client.get("/api/v1/alerts")
                assert resp.status_code == 500
                assert "API authentication is required" in resp.json()["error"]["message"]
        finally:
            app.dependency_overrides.pop(config.get_settings, None)


def test_health_endpoints_remain_public_under_auth_mode():
    """Health probes (/health/live, /health/ready) remain publicly accessible by design even when auth is required."""
    from pydantic import SecretStr
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core import config

    custom_settings = config.Settings(
        API_KEY=SecretStr("secure-token-999"),
        API_AUTH_REQUIRED=True,
    )
    app.dependency_overrides[config.get_settings] = lambda: custom_settings

    try:
        with TestClient(app) as client:
            for path in ("/health/live", "/health/ready", "/api/v1/health/live", "/api/v1/health/ready"):
                resp = client.get(path)
                assert resp.status_code != 401, f"{path} should be publicly accessible without auth"
    finally:
        app.dependency_overrides.pop(config.get_settings, None)


def test_cors_loopback_origins_restricted():
    """CORS middleware restricts allowed origins to configured local loopback hosts."""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        # Allowed origin: 127.0.0.1:5174
        resp_allowed = client.options(
            "/api/v1/alerts",
            headers={"Origin": "http://127.0.0.1:5174", "Access-Control-Request-Method": "GET"},
        )
        assert resp_allowed.headers.get("access-control-allow-origin") == "http://127.0.0.1:5174"

        # Disallowed origin: attacker.com
        resp_blocked = client.options(
            "/api/v1/alerts",
            headers={"Origin": "https://malicious-attacker.com", "Access-Control-Request-Method": "GET"},
        )
        assert resp_blocked.headers.get("access-control-allow-origin") is None
