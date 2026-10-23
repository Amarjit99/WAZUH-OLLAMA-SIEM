"""Evidence-grounded AI investigation schemas conforming to specs/AI_SAFETY_RULES.md and specs/DATA_SCHEMA.md."""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ConfidenceLabel(str, Enum):
    """Qualitative confidence rubric. Does not represent mathematical probability."""
    HIGH = "high"          # Directly supported by multiple corroborating evidence items
    MEDIUM = "medium"      # Supported by single evidence item with clear source context
    LOW = "low"            # Plausible inference with partial or ambiguous evidence
    UNVERIFIED = "unverified"  # Hypothesis lacking direct corroborating log records


class UncertaintyLevel(str, Enum):
    """Explicit uncertainty level for investigative hypotheses."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PriorityLevel(str, Enum):
    """Investigative check priority."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class InvestigationStatus(str, Enum):
    """Status of an AI investigation job."""
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


# =====================================================================
# Server-Constructed Evidence Package (Sent into Prompt Context)
# =====================================================================

class EvidenceItem(BaseModel):
    """An individual authoritative evidence record extracted from SIEM alerts or logs."""
    model_config = ConfigDict(extra="ignore")

    evidence_id: str = Field(description="Unique stable reference ID (e.g. EV-01, EV-02)")
    source_record_id: str = Field(description="Authoritative source ID from Wazuh / OpenSearch")
    event_timestamp: datetime = Field(description="Event timestamp in UTC")
    rule_id: str = Field(description="Wazuh rule ID")
    rule_level: Optional[int] = Field(default=None, description="Wazuh rule level (1-16)")
    rule_description: str = Field(default="", description="Human-readable rule title")
    agent_name: Optional[str] = Field(default=None, description="Monitored agent hostname")
    source_ip: Optional[str] = Field(default=None, description="Source IP address if present")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address if present")
    username: Optional[str] = Field(default=None, description="Associated account or user identity")
    location: Optional[str] = Field(default=None, description="Log file or origin socket")
    raw_evidence_ref: str = Field(description="Pointer to source document (e.g. index/doc_id)")
    is_primary: bool = Field(default=False, description="True if primary investigated alert (EV-01)")
    correlation_reason: Optional[str] = Field(
        default=None,
        description="Observable correlation basis: same_agent, shared_source_ip, shared_destination_ip, shared_username, or temporal_only",
    )
    correlation_qualifier: Optional[str] = Field(
        default=None,
        description="Structured qualifier: e.g. 'network_association_subject_to_nat_dhcp_or_shared_egress', 'generic_account_name_unverified_identity'",
    )
    sanitized_event_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Bounded, sanitized event key-values with sensitive tokens/passwords redacted",
    )


class RelatedEventsSummary(BaseModel):
    """Structured provenance summary of related-event correlation."""
    model_config = ConfigDict(extra="ignore")

    correlation_status: str = Field(
        description="Outcome: 'enriched', 'partial', 'no_related_events_found', 'skipped_not_requested', or 'failed_fallback_single_alert'"
    )
    retrieved_count: int = Field(default=0, description="Total candidate related events retrieved from OpenSearch")
    included_count: int = Field(default=0, description="Total related events included in evidence package")
    truncated_count: int = Field(default=0, description="Candidate events truncated due to event count or byte limits")
    window_minutes: int = Field(default=30, description="Total correlation window in minutes around anchor (± window/2)")
    anchor_timestamp: Optional[datetime] = Field(default=None, description="Anchor event timestamp in UTC")
    unsupported_signals: Optional[List[str]] = Field(
        default_factory=lambda: ["process_lineage", "command_line"],
        description="Signals not represented in the normalized alert evidence schema for this investigation",
    )


class EvidencePackage(BaseModel):
    """Bounded, minimized evidence bundle constructed exclusively by the backend."""
    model_config = ConfigDict(extra="ignore")

    package_id: str = Field(description="Unique identifier for this evidence bundle")
    alert_id: str = Field(description="Primary investigated alert ID")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    items: List[EvidenceItem] = Field(description="Authoritative evidence records provided to LLM context")
    total_events: int = Field(description="Count of included evidence items")
    total_bytes: int = Field(description="Estimated byte size of serialized evidence package")
    redactions_applied: bool = Field(default=False, description="True if sensitive tokens or credentials were scrubbed")
    correlation_status: Optional[str] = Field(default=None, description="Correlation outcome status")
    related_events_summary: Optional[RelatedEventsSummary] = Field(
        default=None,
        description="Structured provenance summary of related-event correlation",
    )


# =====================================================================
# Structured AI Output (Validated by Backend against EvidencePackage)
# =====================================================================

class ObservedFact(BaseModel):
    """A factual statement that must cite at least one valid evidence_id."""
    fact_id: str = Field(description="Identifier (e.g. F-1)")
    statement: str = Field(description="Factual claim directly supported by evidence records")
    cited_evidence_ids: List[str] = Field(
        min_length=1,
        description="List of evidence_ids directly corroborating this fact (e.g. ['EV-01'])",
    )


class Hypothesis(BaseModel):
    """An analytical hypothesis or inference clearly distinguished from observed facts."""
    hypothesis_id: str = Field(description="Identifier (e.g. H-1)")
    statement: str = Field(description="Analytical inference, potential threat activity, or interpretation")
    cited_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Supporting evidence_ids if applicable",
    )
    uncertainty: UncertaintyLevel = Field(
        default=UncertaintyLevel.MEDIUM,
        description="Explicit level of analytical uncertainty",
    )


class RecommendedCheck(BaseModel):
    """A recommended read-only defensive investigation step for human SOC analysts."""
    check_id: str = Field(description="Identifier (e.g. C-1)")
    description: str = Field(description="Recommended read-only investigation action (e.g. check auth logs)")
    rationale: str = Field(description="Why this check is advised based on the findings")
    priority: PriorityLevel = Field(default=PriorityLevel.MEDIUM)
    is_read_only: bool = Field(
        default=True,
        description="Must always be True in v1. No automated remediation or command execution allowed.",
    )


class InvestigationResult(BaseModel):
    """Validated AI investigation record adhering to specs/AI_SAFETY_RULES.md."""
    model_config = ConfigDict(extra="ignore")

    investigation_id: str = Field(description="Unique ID for this investigation")
    alert_id: str = Field(description="Target authoritative alert ID")
    status: InvestigationStatus = Field(description="Investigation validation status")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_name: str = Field(description="Local model family name")
    model_tag: str = Field(description="Exact configured model tag version")
    prompt_version: str = Field(default="v1.0", description="Version of the prompt template used")
    schema_version: str = Field(default="v1.0", description="Version of the output schema")

    summary: str = Field(description="High-level narrative summary of findings")
    observed_facts: List[ObservedFact] = Field(
        default_factory=list,
        description="Observed facts strictly citing provided evidence IDs",
    )
    hypotheses: List[Hypothesis] = Field(
        default_factory=list,
        description="Inferences and hypotheses with explicit uncertainty labels",
    )
    recommended_checks: List[RecommendedCheck] = Field(
        default_factory=list,
        description="Defensive, read-only checks for human analysts",
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Known gaps in available evidence, missing context, or blind spots",
    )
    confidence_label: ConfidenceLabel = Field(
        default=ConfidenceLabel.LOW,
        description="Qualitative assessment based on evidence coverage rubric",
    )
    unsupported_citation_warnings: List[str] = Field(
        default_factory=list,
        description="Backend validation warnings for cited IDs that were not in the evidence package",
    )
    correlation_status: Optional[str] = Field(
        default=None,
        description="Correlation outcome status (enriched, no_related_events_found, skipped_not_requested, failed_fallback_single_alert)",
    )
    related_events_summary: Optional[RelatedEventsSummary] = Field(
        default=None,
        description="Structured provenance summary of related event correlation",
    )
    disclaimer: str = Field(
        default="Advisory AI analysis only. Not an authoritative detection or automated response order.",
        description="Mandatory advisory notice",
    )
    evidence_items: Optional[List[EvidenceItem]] = Field(
        default=None,
        description="Authoritative, bounded evidence items evaluated in this investigation",
    )


SPECULATIVE_WORDS = re.compile(
    r"\b(may indicate|might be|could be|possibly|perhaps|suspected to be|likely represents)\b",
    re.IGNORECASE,
)
INSIDER_ATTRIBUTION = re.compile(r"\b(insider\s+(?:threat|attack|actor|activity))\b", re.IGNORECASE)
NATION_STATE_ATTRIBUTION = re.compile(
    r"\b(nation[- ]state|advanced persistent threat|apt\d+|state[- ]sponsored)\b",
    re.IGNORECASE,
)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ATTACKER_INTENT_PATTERN = re.compile(
    r"\b(attacker attempting|malicious actor hiding|adversary active|confirmed compromise|attacker hiding|hiding malicious activity)\b",
    re.IGNORECASE,
)
REMEDIATION_PATTERN = re.compile(
    r"\b(block ip|disable account|kill process|isolate host|drop table|reboot system|quarantine file|iptables|ufw)\b",
    re.IGNORECASE,
)
PROCESS_CORRELATION_PATTERN = re.compile(
    r"\b(spawned process|process lineage|parent process|child process|process injection|injected into process)\b",
    re.IGNORECASE,
)
LATERAL_MOVEMENT_PATTERN = re.compile(
    r"\b(lateral movement|pivoting across hosts|compromised host communicating with)\b",
    re.IGNORECASE,
)
CAUSAL_TEMPORAL_PATTERN = re.compile(
    r"\b(proves compromise|causes the alert|directly caused by|conclusively establishes an attack)\b",
    re.IGNORECASE,
)
SHARED_ATTACKER_PATTERN = re.compile(
    r"\b(same attacker|common attacker|single actor|same adversary|coordinated attack campaign|shared threat actor)\b",
    re.IGNORECASE,
)
GENERIC_ACCOUNT_IDENTITY_PATTERN = re.compile(
    r"\b(same user account|same person|user pivoting|account compromised across hosts|same operator)\b",
    re.IGNORECASE,
)

# ponytail: Deterministic regex and lexical pattern matching cannot perform full natural language entailment (NLI).
# Known ceiling: Novel phrasing, indirect inferences, or subtle semantic drift can evade keyword checks.
# Upgrade path: A quantized local cross-encoder NLI model (e.g., DeBERTa-v3-small/ONNX) once dedicated GPU/NPU budget is allocated.


def validate_evidence_citations(
    result: InvestigationResult,
    package: EvidencePackage,
) -> List[str]:
    """Verify citation validity, factual grounding, attribution sanity, and confidence calibration.

    Adheres to specs/AI_SAFETY_RULES.md:
    1. Cited IDs must exist in the exact supplied evidence package.
    2. Citation validity does NOT equate to factual truth: check for uncorroborated attributions.
    3. Speculative language belongs in hypotheses, not observed facts.
    4. Isolated rootkit alerts do not establish active attacker intent without corroborating telemetry.
    5. Single uncorroborated alerts cannot claim high confidence.
    6. All recommended checks must be strictly read-only (no remediation).
    """
    valid_ids = {item.evidence_id for item in package.items}
    warnings: List[str] = []

    # Extract all known text, IPs, and usernames from the evidence package
    package_usernames = {item.username.lower() for item in package.items if item.username}
    package_ips = set()
    is_rootcheck_alert = False
    for item in package.items:
        if item.source_ip:
            package_ips.add(item.source_ip)
        if item.destination_ip:
            package_ips.add(item.destination_ip)
        if item.rule_id == "521" or "rootkit" in (item.rule_description or "").lower() or (item.location or "").lower() == "rootcheck":
            is_rootcheck_alert = True

    # 1. Validate Observed Facts
    for fact in result.observed_facts:
        if not fact.cited_evidence_ids:
            warnings.append(f"Fact '{fact.fact_id}' does not cite any evidence IDs.")
        for cited_id in fact.cited_evidence_ids:
            if cited_id not in valid_ids:
                warnings.append(f"Fact '{fact.fact_id}' cites non-existent evidence ID '{cited_id}'")

        # Check: Speculative language in observed facts
        spec_match = SPECULATIVE_WORDS.search(fact.statement)
        if spec_match:
            warnings.append(
                f"Fact '{fact.fact_id}' contains speculative wording ('{spec_match.group(0)}'); "
                "inferences must be categorized under hypotheses."
            )

        # Check: Fabricated IP addresses in facts
        mentioned_ips = IP_REGEX.findall(fact.statement)
        for ip in mentioned_ips:
            if ip not in package_ips:
                warnings.append(
                    f"Fact '{fact.fact_id}' claims IP '{ip}' which does not appear in the evidence package."
                )

    # 2. Validate Hypotheses
    for hyp in result.hypotheses:
        if not hyp.cited_evidence_ids:
            warnings.append(f"Hypothesis '{hyp.hypothesis_id}' does not cite any evidence IDs.")
        for cited_id in hyp.cited_evidence_ids:
            if cited_id not in valid_ids:
                warnings.append(f"Hypothesis '{hyp.hypothesis_id}' cites non-existent evidence ID '{cited_id}'")

        # Check: Unsupported insider threat attribution without user context
        if INSIDER_ATTRIBUTION.search(hyp.statement) and not package_usernames:
            warnings.append(
                f"Hypothesis '{hyp.hypothesis_id}' asserts insider threat attribution, "
                "but the evidence package contains no user identity or authentication context."
            )

        # Check: Unsupported nation-state / APT attribution without threat intel
        if NATION_STATE_ATTRIBUTION.search(hyp.statement):
            warnings.append(
                f"Hypothesis '{hyp.hypothesis_id}' asserts advanced persistent threat / nation-state attribution "
                "without supporting threat intelligence evidence."
            )

        # Check: Isolated rootkit alert claiming active attacker intent without corroborating telemetry
        if is_rootcheck_alert and package.total_events <= 1 and ATTACKER_INTENT_PATTERN.search(hyp.statement):
            warnings.append(
                f"Hypothesis '{hyp.hypothesis_id}' asserts active attacker intent for an isolated rootkit alert "
                "without corroborating process lineage, network activity, or file integrity telemetry."
            )

        # Check: Unsupported process correlation claim when alert schema lacks process telemetry
        if PROCESS_CORRELATION_PATTERN.search(hyp.statement):
            warnings.append(
                f"Hypothesis '{hyp.hypothesis_id}' asserts process lineage or injection, "
                "but the evidence package contains no normalized process telemetry."
            )

        # Check: Unsupported lateral movement claim without network telemetry
        if LATERAL_MOVEMENT_PATTERN.search(hyp.statement) and not package_ips:
            warnings.append(
                f"Hypothesis '{hyp.hypothesis_id}' asserts lateral movement / pivoting, "
                "but the evidence package contains no network flow or IP correlation telemetry."
            )

        # Check: Unwarranted causal claims (correlation != causation)
        if CAUSAL_TEMPORAL_PATTERN.search(hyp.statement):
            warnings.append(
                f"Hypothesis '{hyp.hypothesis_id}' asserts absolute causality or confirmed compromise; "
                "correlation does not prove causation or attacker intent."
            )

        # Check: Unsupported shared-attacker claim based only on IP or temporal association
        if SHARED_ATTACKER_PATTERN.search(hyp.statement):
            has_strong_corroboration = any(
                item.correlation_reason and item.correlation_reason == "shared_username"
                for item in package.items[1:]
            )
            if not has_strong_corroboration:
                warnings.append(
                    f"Hypothesis '{hyp.hypothesis_id}' asserts a shared or common attacker based solely on shared network attributes (IP) "
                    "or temporal proximity; IP matches may stem from NAT, DHCP, proxying, or address reuse."
                )

        # Check: Generic account treated as verified human identity or user pivoting
        if GENERIC_ACCOUNT_IDENTITY_PATTERN.search(hyp.statement):
            generic_set = {"root", "admin", "administrator", "system", "service", "daemon", "guest", "nobody", "test"}
            if package_usernames and package_usernames.issubset(generic_set):
                warnings.append(
                    f"Hypothesis '{hyp.hypothesis_id}' asserts common user identity across hosts, "
                    "but evidence package contains only generic account names which does not prove individual identity."
                )

    # 3. Validate Recommended Checks (Strictly Read-Only)
    for check in result.recommended_checks:
        if not check.is_read_only:
            check.is_read_only = True
            warnings.append(
                f"Check '{check.check_id}' requested active remediation, which is prohibited; forced to read-only."
            )
        elif REMEDIATION_PATTERN.search(check.description):
            warnings.append(
                f"Check '{check.check_id}' mentions remediation actions ('{check.description}'); only read-only investigative verification is permitted."
            )

    # 4. Enforce Limitations on Sparse Evidence
    if package.total_events <= 1 and not result.limitations:
        result.limitations.append(
            "Single isolated alert evaluated without historical baseline, network telemetry, or host process logs."
        )

    # 5. Confidence Calibration Guardrail
    only_weak_temporal = (
        package.total_events > 1
        and all(item.correlation_reason and "temporal" in item.correlation_reason.lower() for item in package.items[1:])
    )
    only_generic_account = (
        package.total_events > 1
        and all(item.correlation_reason and "generic account" in item.correlation_reason.lower() for item in package.items[1:])
    )
    if (package.total_events <= 1 or only_weak_temporal or only_generic_account) and result.confidence_label == ConfidenceLabel.HIGH:
        result.confidence_label = ConfidenceLabel.MEDIUM
        warnings.append(
            "Confidence calibrated from HIGH to MEDIUM: correlation relies exclusively on an isolated alert, "
            "weak temporal proximity, or uncorroborated generic account names without corroborating host or entity telemetry."
        )

    return warnings


class InvestigationRequest(BaseModel):
    """Request payload for proposing an alert investigation."""
    alert_id: Optional[str] = Field(
        default=None,
        description="Authoritative alert document ID to investigate (derived from path parameter if omitted)",
    )
    include_related_events: bool = Field(
        default=False,
        description="Whether to search for related events on the same host or source IP",
    )
    correlation_window_minutes: int = Field(
        default=30,
        ge=5,
        le=60,
        description="Total correlation time window in minutes around anchor alert (5 to 60, default 30)",
    )
    max_related_events: int = Field(
        default=10,
        ge=1,
        le=20,
        description="Maximum related events to correlate (1 to 20, default 10)",
    )
    max_evidence_items: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of evidence records to supply in model context (capped at 50)",
    )
