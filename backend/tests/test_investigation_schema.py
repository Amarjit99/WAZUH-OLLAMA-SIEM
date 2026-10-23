"""Unit tests for AI investigation schemas and evidence citation validation rules."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.schemas.investigation import (
    ConfidenceLabel,
    EvidenceItem,
    EvidencePackage,
    Hypothesis,
    InvestigationRequest,
    InvestigationResult,
    InvestigationStatus,
    ObservedFact,
    PriorityLevel,
    RecommendedCheck,
    UncertaintyLevel,
    validate_evidence_citations,
)


def create_sample_evidence_package() -> EvidencePackage:
    """Helper to build a valid sample evidence package."""
    now = datetime.now(timezone.utc)
    items = [
        EvidenceItem(
            evidence_id="EV-01",
            source_record_id="doc-alert-001",
            event_timestamp=now,
            rule_id="5710",
            rule_level=5,
            rule_description="sshd: Attempt to login using a non-existent user",
            agent_name="wazuh-manager",
            source_ip="192.168.1.100",
            username="invalid_user",
            location="/var/log/auth.log",
            raw_evidence_ref="wazuh-alerts-4.x/doc-alert-001",
            sanitized_event_data={"srcuser": "invalid_user", "srcip": "192.168.1.100"},
        ),
        EvidenceItem(
            evidence_id="EV-02",
            source_record_id="doc-alert-002",
            event_timestamp=now,
            rule_id="5501",
            rule_level=3,
            rule_description="PAM: User login failed",
            agent_name="wazuh-manager",
            source_ip="192.168.1.100",
            username="root",
            location="/var/log/secure",
            raw_evidence_ref="wazuh-alerts-4.x/doc-alert-002",
            sanitized_event_data={"srcip": "192.168.1.100"},
        ),
    ]
    return EvidencePackage(
        package_id="pkg-12345",
        alert_id="doc-alert-001",
        created_at=now,
        items=items,
        total_events=len(items),
        total_bytes=1500,
        redactions_applied=True,
    )


def test_evidence_package_model_valid():
    """Verify EvidencePackage and EvidenceItem models serialize cleanly."""
    pkg = create_sample_evidence_package()
    assert pkg.package_id == "pkg-12345"
    assert pkg.total_events == 2
    assert pkg.items[0].evidence_id == "EV-01"
    assert pkg.items[1].rule_id == "5501"


def test_observed_fact_requires_at_least_one_evidence_citation():
    """Verify ObservedFact enforces cited_evidence_ids has at least 1 item."""
    # Valid fact
    fact = ObservedFact(
        fact_id="F-1",
        statement="Failed SSH login from 192.168.1.100",
        cited_evidence_ids=["EV-01"],
    )
    assert fact.cited_evidence_ids == ["EV-01"]

    # Invalid: empty citations must raise ValidationError
    with pytest.raises(ValidationError):
        ObservedFact(
            fact_id="F-2",
            statement="Unsupported claim without evidence",
            cited_evidence_ids=[],
        )


def test_recommended_checks_must_be_read_only():
    """Verify RecommendedCheck defaults to is_read_only=True."""
    check = RecommendedCheck(
        check_id="C-1",
        description="Verify authentication logs for 192.168.1.100",
        rationale="Corroborate repeated authentication attempts",
        priority=PriorityLevel.HIGH,
    )
    assert check.is_read_only is True


def test_citation_validator_detects_hallucinated_evidence_ids():
    """Verify backend validator detects and flags citations not in EvidencePackage."""
    package = create_sample_evidence_package()  # Contains EV-01 and EV-02

    now = datetime.now(timezone.utc)
    result = InvestigationResult(
        investigation_id="inv-999",
        alert_id="doc-alert-001",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="qwen2.5",
        model_tag="qwen2.5:7b-instruct",
        summary="Analysis of repeated failed authentication",
        observed_facts=[
            ObservedFact(fact_id="F-1", statement="Real fact", cited_evidence_ids=["EV-01"]),
            ObservedFact(fact_id="F-2", statement="Hallucinated fact", cited_evidence_ids=["EV-99"]),
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="Possible brute force",
                cited_evidence_ids=["EV-02", "EV-88"],
                uncertainty=UncertaintyLevel.HIGH,
            )
        ],
        recommended_checks=[
            RecommendedCheck(
                check_id="C-1",
                description="Query recent auth events",
                rationale="Review failure volume",
            )
        ],
        confidence_label=ConfidenceLabel.MEDIUM,
    )

    warnings = validate_evidence_citations(result, package)
    assert len(warnings) == 2
    assert any("EV-99" in w for w in warnings)
    assert any("EV-88" in w for w in warnings)


def test_investigation_request_limits_evidence_items():
    """Verify max_evidence_items enforces boundary between 1 and 50."""
    req_valid = InvestigationRequest(alert_id="alert-1", max_evidence_items=25)
    assert req_valid.max_evidence_items == 25

    with pytest.raises(ValidationError):
        InvestigationRequest(alert_id="alert-1", max_evidence_items=0)

    with pytest.raises(ValidationError):
        InvestigationRequest(alert_id="alert-1", max_evidence_items=100)


def test_unsupported_insider_threat_attribution_flagged():
    """Verify hypothesis claiming insider threat without user context is flagged."""
    now = datetime.now(timezone.utc)
    # Evidence package without any username or authentication log (like rootcheck)
    items = [
        EvidenceItem(
            evidence_id="EV-01",
            source_record_id="doc-521",
            event_timestamp=now,
            rule_id="521",
            rule_level=11,
            rule_description="Possible kernel level rootkit",
            agent_name="wazuh.manager",
            location="rootcheck",
            raw_evidence_ref="wazuh-alerts/doc-521",
        )
    ]
    pkg = EvidencePackage(
        package_id="pkg-rootcheck",
        alert_id="doc-521",
        created_at=now,
        items=items,
        total_events=1,
        total_bytes=500,
    )

    result = InvestigationResult(
        investigation_id="inv-attr-001",
        alert_id="doc-521",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Rootkit detection analysis",
        observed_facts=[
            ObservedFact(fact_id="F-1", statement="Rootkit alert triggered", cited_evidence_ids=["EV-01"])
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="The rootkit indicates an insider threat attempting to hide data",
                cited_evidence_ids=["EV-01"],
                uncertainty=UncertaintyLevel.MEDIUM,
            )
        ],
        recommended_checks=[
            RecommendedCheck(
                check_id="C-1",
                description="Check system logs",
                rationale="Confirm detection",
            )
        ],
        confidence_label=ConfidenceLabel.LOW,
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("insider threat attribution" in w for w in warnings)


def test_unsupported_nation_state_attribution_flagged():
    """Verify hypothesis asserting nation-state or APT without threat intel is flagged."""
    pkg = create_sample_evidence_package()
    now = datetime.now(timezone.utc)

    result = InvestigationResult(
        investigation_id="inv-apt-001",
        alert_id="doc-alert-001",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Authentication failures",
        observed_facts=[
            ObservedFact(fact_id="F-1", statement="Login failed", cited_evidence_ids=["EV-01"])
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="Activity is linked to an advanced persistent threat (APT) actor",
                cited_evidence_ids=["EV-01"],
                uncertainty=UncertaintyLevel.HIGH,
            )
        ],
        recommended_checks=[],
        confidence_label=ConfidenceLabel.LOW,
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("advanced persistent threat" in w for w in warnings)


def test_speculative_wording_in_observed_facts_flagged():
    """Verify observed facts containing speculative wording are flagged."""
    pkg = create_sample_evidence_package()
    now = datetime.now(timezone.utc)

    result = InvestigationResult(
        investigation_id="inv-spec-001",
        alert_id="doc-alert-001",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Authentication test",
        observed_facts=[
            ObservedFact(
                fact_id="F-1",
                statement="The failed login may indicate an ongoing reconnaissance campaign",
                cited_evidence_ids=["EV-01"],
            )
        ],
        hypotheses=[],
        recommended_checks=[],
        confidence_label=ConfidenceLabel.LOW,
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("contains speculative wording" in w for w in warnings)


def test_fabricated_ip_address_in_fact_flagged():
    """Verify observed facts claiming an unevidenced IP address are flagged."""
    pkg = create_sample_evidence_package()  # Package only contains 192.168.1.100
    now = datetime.now(timezone.utc)

    result = InvestigationResult(
        investigation_id="inv-ip-001",
        alert_id="doc-alert-001",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Authentication test",
        observed_facts=[
            ObservedFact(
                fact_id="F-1",
                statement="Attack originated from 10.0.0.99 targeting server",
                cited_evidence_ids=["EV-01"],
            )
        ],
        hypotheses=[],
        recommended_checks=[],
        confidence_label=ConfidenceLabel.LOW,
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("claims IP '10.0.0.99'" in w for w in warnings)


def test_confidence_calibration_downgrades_high_on_single_alert():
    """Verify single alert claiming HIGH confidence is calibrated down to MEDIUM."""
    now = datetime.now(timezone.utc)
    items = [
        EvidenceItem(
            evidence_id="EV-01",
            source_record_id="doc-1",
            event_timestamp=now,
            rule_id="5710",
            rule_level=5,
            rule_description="SSH login failed",
            agent_name="server-1",
            raw_evidence_ref="alerts/doc-1",
        )
    ]
    pkg = EvidencePackage(
        package_id="pkg-single",
        alert_id="doc-1",
        created_at=now,
        items=items,
        total_events=1,
        total_bytes=300,
    )

    result = InvestigationResult(
        investigation_id="inv-cal-001",
        alert_id="doc-1",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Single event analysis",
        observed_facts=[
            ObservedFact(fact_id="F-1", statement="SSH login failed", cited_evidence_ids=["EV-01"])
        ],
        hypotheses=[],
        recommended_checks=[],
        confidence_label=ConfidenceLabel.HIGH,  # Unjustified high confidence
    )

    warnings = validate_evidence_citations(result, pkg)
    assert result.confidence_label == ConfidenceLabel.MEDIUM
    assert any("Confidence calibrated from HIGH to MEDIUM" in w for w in warnings)


def test_isolated_rootkit_attacker_intent_flagged():
    """Verify an isolated rootkit alert asserting active attacker intent is flagged."""
    now = datetime.now(timezone.utc)
    items = [
        EvidenceItem(
            evidence_id="EV-01",
            source_record_id="doc-521",
            event_timestamp=now,
            rule_id="521",
            rule_level=11,
            rule_description="Possible kernel level rootkit",
            agent_name="wazuh.manager",
            location="rootcheck",
            raw_evidence_ref="wazuh-alerts/doc-521",
        )
    ]
    pkg = EvidencePackage(
        package_id="pkg-rootcheck",
        alert_id="doc-521",
        created_at=now,
        items=items,
        total_events=1,
        total_bytes=500,
    )

    result = InvestigationResult(
        investigation_id="inv-intent-001",
        alert_id="doc-521",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Rootkit detection analysis",
        observed_facts=[
            ObservedFact(fact_id="F-1", statement="Rootkit alert triggered", cited_evidence_ids=["EV-01"])
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="H-1",
                statement="The detected rootkit may be a sign of an attacker attempting to hide malicious activity at kernel level",
                cited_evidence_ids=["EV-01"],
                uncertainty=UncertaintyLevel.MEDIUM,
            )
        ],
        recommended_checks=[
            RecommendedCheck(
                check_id="C-1",
                description="Inspect /proc filesystem for hidden processes",
                rationale="Verify anomaly",
            )
        ],
        limitations=["Single alert without host process telemetry"],
        confidence_label=ConfidenceLabel.LOW,
    )

    warnings = validate_evidence_citations(result, pkg)
    assert any("asserts active attacker intent for an isolated rootkit alert" in w for w in warnings)


def test_remediation_action_in_recommended_checks_flagged_and_forced_readonly():
    """Verify active remediation actions in recommended checks are prohibited, flagged, and forced read-only."""
    pkg = create_sample_evidence_package()
    now = datetime.now(timezone.utc)

    result = InvestigationResult(
        investigation_id="inv-remed-001",
        alert_id="doc-alert-001",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Analysis with remediation attempt",
        observed_facts=[
            ObservedFact(fact_id="F-1", statement="Failed login attempt", cited_evidence_ids=["EV-01"])
        ],
        hypotheses=[],
        recommended_checks=[
            RecommendedCheck(
                check_id="C-1",
                description="block ip using iptables firewall rule immediately",
                rationale="Stop attack",
                is_read_only=False,
            )
        ],
        limitations=["None"],
        confidence_label=ConfidenceLabel.LOW,
    )

    warnings = validate_evidence_citations(result, pkg)
    # Check must be forced to read-only
    assert result.recommended_checks[0].is_read_only is True
    assert any("prohibited" in w or "mentions remediation actions" in w for w in warnings)


def test_sparse_evidence_missing_limitations_injects_note():
    """Verify a single isolated alert with empty limitations receives a fallback limitation note."""
    now = datetime.now(timezone.utc)
    items = [
        EvidenceItem(
            evidence_id="EV-01",
            source_record_id="doc-sparse",
            event_timestamp=now,
            rule_id="5710",
            rule_level=5,
            rule_description="SSH login failed",
            agent_name="server-1",
            raw_evidence_ref="alerts/doc-sparse",
        )
    ]
    pkg = EvidencePackage(
        package_id="pkg-sparse",
        alert_id="doc-sparse",
        created_at=now,
        items=items,
        total_events=1,
        total_bytes=300,
    )

    result = InvestigationResult(
        investigation_id="inv-sparse-001",
        alert_id="doc-sparse",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Single alert without limitations",
        observed_facts=[
            ObservedFact(fact_id="F-1", statement="Login failed", cited_evidence_ids=["EV-01"])
        ],
        hypotheses=[],
        recommended_checks=[],
        limitations=[],  # Empty limitations on sparse evidence
        confidence_label=ConfidenceLabel.LOW,
    )

    validate_evidence_citations(result, pkg)
    assert len(result.limitations) > 0
    assert "Single isolated alert" in result.limitations[0]


def test_investigation_result_carries_evidence_items_provenance():
    """Verify InvestigationResult carries evidence_items with full provenance and serializes correctly."""
    now = datetime.now(timezone.utc)
    ev_item = EvidenceItem(
        evidence_id="EV-01",
        source_record_id="alert-doc-001",
        event_timestamp=now,
        is_primary=True,
        rule_id="5710",
        rule_level=5,
        rule_description="sshd: Attempt to login using a non-existent user",
        agent_name="production-db-01",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        username="postgres",
        correlation_reason="primary_investigation_target",
        correlation_qualifier="reporting_endpoint_context_only",
        raw_evidence_ref="wazuh-alerts/alert-doc-001",
    )

    result = InvestigationResult(
        investigation_id="inv-prov-001",
        alert_id="alert-doc-001",
        status=InvestigationStatus.VALID,
        generated_at=now,
        model_name="ollama",
        model_tag="llama3.2:3b",
        summary="Verified provenance carried in result.",
        observed_facts=[
            ObservedFact(fact_id="F-1", statement="Failed login attempt for postgres", cited_evidence_ids=["EV-01"])
        ],
        hypotheses=[],
        recommended_checks=[],
        evidence_items=[ev_item],
        confidence_label=ConfidenceLabel.LOW,
    )

    # Test serialization round-trip
    dumped = result.model_dump()
    assert "evidence_items" in dumped
    assert len(dumped["evidence_items"]) == 1
    ev_dump = dumped["evidence_items"][0]
    assert ev_dump["evidence_id"] == "EV-01"
    assert ev_dump["is_primary"] is True
    assert ev_dump["source_ip"] == "192.168.1.50"
    assert ev_dump["correlation_qualifier"] == "reporting_endpoint_context_only"

    # Test deserialization
    reconstructed = InvestigationResult.model_validate(dumped)
    assert reconstructed.evidence_items is not None
    assert reconstructed.evidence_items[0].evidence_id == "EV-01"
    assert reconstructed.evidence_items[0].rule_description == "sshd: Attempt to login using a non-existent user"



