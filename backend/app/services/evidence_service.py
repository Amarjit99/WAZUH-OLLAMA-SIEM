"""Evidence retrieval, minimization, and sanitization service.

Conforms to:
- specs/AI_SAFETY_RULES.md (Evidence grounding, prompt injection, data minimization)
- specs/DATA_SCHEMA.md (EvidencePackage, EvidenceItem)
- specs/SECURITY_THREAT_MODEL.md (Prompt injection through logs, sensitive data leakage)
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import Settings, get_settings
from app.schemas.alert import NormalizedAlert
from app.schemas.investigation import EvidenceItem, EvidencePackage, RelatedEventsSummary
from app.services.opensearch_client import OpenSearchClient

logger = logging.getLogger("siem.evidence_service")

# Keys that may contain secrets to be redacted
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|passwd|secret|token|api_?key|bearer|authorization|cookie|session_?id|private_?key)",
    re.IGNORECASE,
)

# Truncate individual field strings to prevent context flooding
MAX_FIELD_LENGTH = 500

# String placeholders that must never be treated as valid correlation entities
INVALID_PLACEHOLDERS = frozenset({
    "",
    "unknown",
    "none",
    "null",
    "-",
    "n/a",
    "undefined",
    "any",
})


def is_valid_ip(ip: Optional[str]) -> bool:
    """Validate that string is a non-empty, non-placeholder, non-loopback IP address."""
    if not ip or not isinstance(ip, str):
        return False
    val = ip.strip().lower()
    if val in INVALID_PLACEHOLDERS or val in ("0.0.0.0", "::", "127.0.0.1", "::1", "localhost"):
        return False
    try:
        addr = ipaddress.ip_address(val)
        if addr.is_unspecified or addr.is_loopback:
            return False
        return True
    except ValueError:
        return False


def is_valid_username(user: Optional[str]) -> bool:
    """Validate that string is a non-empty, non-placeholder username."""
    if not user or not isinstance(user, str):
        return False
    val = user.strip().lower()
    return val not in INVALID_PLACEHOLDERS


# Common / generic account names that do not verify individual identity across endpoints
GENERIC_USERNAMES = frozenset({
    "root",
    "admin",
    "administrator",
    "system",
    "service",
    "daemon",
    "guest",
    "nobody",
    "test",
    "localadmin",
    "support",
})


def is_generic_username(user: Optional[str]) -> bool:
    """Check if username is a common/generic account name subject to false identity association."""
    if not user or not isinstance(user, str):
        return False
    return user.strip().lower() in GENERIC_USERNAMES


def is_valid_agent(agent_val: Optional[str]) -> bool:
    """Validate that agent/host identifier is non-empty and non-placeholder."""
    if not agent_val or not isinstance(agent_val, str):
        return False
    val = agent_val.strip().lower()
    return val not in INVALID_PLACEHOLDERS


def sanitize_value(val: Any) -> Any:
    """Recursively sanitize field values, redacting potential credentials and truncating oversized strings."""
    if isinstance(val, str):
        if len(val) > MAX_FIELD_LENGTH:
            return val[:MAX_FIELD_LENGTH] + "... [truncated]"
        return val
    elif isinstance(val, dict):
        cleaned = {}
        for k, v in val.items():
            if SENSITIVE_KEY_PATTERNS.search(str(k)):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_value(v)
        return cleaned
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val[:20]]  # Bound lists to 20 items
    return val


def alert_to_evidence_item(
    alert: NormalizedAlert,
    evidence_id: str,
    is_primary: bool = False,
    correlation_reason: Optional[str] = None,
) -> EvidenceItem:
    """Convert an authoritative NormalizedAlert into a sanitized EvidenceItem."""
    sanitized_data: Dict[str, Any] = {
        "rule_level": alert.rule_level,
        "rule_id": alert.rule_id,
        "rule_description": alert.rule_description,
        "location": alert.location,
    }
    if alert.full_log:
        sanitized_data["full_log"] = sanitize_value(alert.full_log)
    if alert.raw_document:
        sanitized_data["details"] = sanitize_value(alert.raw_document)

    correlation_qualifier = None
    if correlation_reason:
        r_lower = correlation_reason.lower()
        if "shared_source_ip" in r_lower or "shared_destination_ip" in r_lower:
            correlation_qualifier = "network_association_subject_to_nat_dhcp_or_shared_egress"
        elif "generic account" in r_lower:
            correlation_qualifier = "generic_account_name_unverified_identity"
        elif "temporal" in r_lower:
            correlation_qualifier = "temporal_proximity_only_non_causal"
        elif "same_agent" in r_lower:
            correlation_qualifier = "reporting_endpoint_context_only"

    return EvidenceItem(
        evidence_id=evidence_id,
        source_record_id=alert.alert_id,
        event_timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        rule_level=alert.rule_level,
        rule_description=alert.rule_description or "",
        agent_name=alert.agent_name or alert.host_name,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        username=alert.username,
        location=alert.location,
        raw_evidence_ref=alert.raw_evidence_ref,
        is_primary=is_primary,
        correlation_reason=correlation_reason,
        correlation_qualifier=correlation_qualifier,
        sanitized_event_data=sanitized_data,
    )


def classify_correlation(rel: NormalizedAlert, primary: NormalizedAlert) -> Tuple[int, str]:
    """Evaluate observable correlation signals and assign deterministic priority and reason.

    Priority 1: Exact shared entity identifiers (IP, verified non-generic username)
    Priority 2: Same agent or generic username match across hosts
    Priority 3: Temporal proximity only (weak signal, non-causal context)
    """
    # 1. Exact shared IP (preserves specific reason; network association subject to NAT/DHCP)
    if is_valid_ip(primary.source_ip):
        if is_valid_ip(rel.source_ip) and rel.source_ip.strip() == primary.source_ip.strip():
            return (1, "shared_source_ip")
        if is_valid_ip(rel.destination_ip) and rel.destination_ip.strip() == primary.source_ip.strip():
            return (1, "shared_source_ip")

    if is_valid_ip(primary.destination_ip):
        if is_valid_ip(rel.destination_ip) and rel.destination_ip.strip() == primary.destination_ip.strip():
            return (1, "shared_destination_ip")
        if is_valid_ip(rel.source_ip) and rel.source_ip.strip() == primary.destination_ip.strip():
            return (1, "shared_destination_ip")

    # 1b. Exact non-generic shared username
    if is_valid_username(primary.username) and is_valid_username(rel.username):
        if primary.username.strip().lower() == rel.username.strip().lower():
            if not is_generic_username(primary.username):
                return (1, "shared_username")

    # 2. Same agent (identifies common reporting endpoint context, not causation)
    if is_valid_agent(primary.agent_id) and is_valid_agent(rel.agent_id):
        if primary.agent_id.strip() == rel.agent_id.strip():
            return (2, "same_agent")

    if is_valid_agent(primary.agent_name) and is_valid_agent(rel.agent_name):
        if primary.agent_name.strip().lower() == rel.agent_name.strip().lower():
            return (2, "same_agent")

    if is_valid_agent(primary.host_name) and is_valid_agent(rel.host_name):
        if primary.host_name.strip().lower() == rel.host_name.strip().lower():
            return (2, "same_agent")

    # 2b. Generic username match (e.g. root, admin) across different hosts/endpoints
    if is_valid_username(primary.username) and is_valid_username(rel.username):
        if primary.username.strip().lower() == rel.username.strip().lower():
            return (2, "shared_username (generic account; does not verify identity or lateral movement)")

    # 3. Temporal proximity only (weak signal, non-causal context)
    return (
        3,
        "temporal_proximity_only (temporal_only weak correlation; temporal proximity does not prove causation or attacker intent)",
    )


class EvidenceService:
    """Builds bounded, minimized, and sanitized evidence packages from OpenSearch alerts."""

    def __init__(self, opensearch: OpenSearchClient, settings: Optional[Settings] = None):
        self.opensearch = opensearch
        self.settings = settings or get_settings()

    async def build_evidence_package(
        self,
        primary_alert: NormalizedAlert,
        package_id: str,
        include_related_events: bool = False,
        correlation_window_minutes: int = 30,
        max_related_events: int = 10,
        max_evidence_items: int = 10,
    ) -> EvidencePackage:
        """Construct an authoritative, bounded EvidencePackage with deterministic correlation."""
        # Enforce server-side maxima
        bounded_max_evidence = min(max(1, max_evidence_items), self.settings.MAX_EVIDENCE_EVENTS)
        bounded_max_related = min(max(1, max_related_events), 20)
        bounded_window_mins = min(max(5, correlation_window_minutes), 60)

        # Primary alert is always EV-01 and must never be displaced
        primary_item = alert_to_evidence_item(
            primary_alert,
            evidence_id="EV-01",
            is_primary=True,
            correlation_reason=None,
        )
        items: List[EvidenceItem] = [primary_item]

        correlation_status = "skipped_not_requested"
        retrieved_count = 0
        truncated_count = 0
        raw_anchor_ts = primary_alert.timestamp

        # Check timestamp validity: do not fabricate if missing or invalid
        ts_invalid = False
        if not raw_anchor_ts:
            ts_invalid = True
            anchor_ts = datetime.now(timezone.utc)
        else:
            if raw_anchor_ts.tzinfo is None:
                anchor_ts = raw_anchor_ts.replace(tzinfo=timezone.utc)
            else:
                anchor_ts = raw_anchor_ts.astimezone(timezone.utc)

            if primary_alert.normalization_warnings:
                for w in primary_alert.normalization_warnings:
                    w_lower = w.lower()
                    if (
                        "timestamp missing" in w_lower
                        or "failed to parse timestamp" in w_lower
                        or "ambiguous timestamp" in w_lower
                        or "untrusted timestamp" in w_lower
                    ):
                        ts_invalid = True
                        break

        if include_related_events:
            if ts_invalid:
                logger.warning(
                    "Alert %s has invalid, ambiguous, or missing timestamp; skipping related-event correlation",
                    primary_alert.alert_id,
                )
                correlation_status = "failed_fallback_single_alert"
            elif bounded_max_evidence <= 1:
                correlation_status = "skipped_not_requested"
            else:
                try:
                    raw_candidates = await self._fetch_candidate_alerts(
                        primary_alert=primary_alert,
                        window_minutes=bounded_window_mins,
                        max_to_fetch=min(bounded_max_related * 2 + 5, 50),
                    )

                    # Strict boundary filtering: start <= cand_ts <= end
                    half_window = timedelta(minutes=bounded_window_mins / 2.0)
                    start_bound = anchor_ts - half_window
                    end_bound = anchor_ts + half_window

                    valid_candidates: List[NormalizedAlert] = []
                    for c in raw_candidates:
                        if not c.timestamp:
                            continue
                        if c.normalization_warnings and any(
                            ("failed to parse timestamp" in w.lower() or "ambiguous timestamp" in w.lower() or "untrusted timestamp" in w.lower())
                            for w in c.normalization_warnings
                        ):
                            continue
                        c_ts = c.timestamp if c.timestamp.tzinfo is not None else c.timestamp.replace(tzinfo=timezone.utc)
                        c_ts = c_ts.astimezone(timezone.utc)
                        if start_bound <= c_ts <= end_bound:
                            c.timestamp = c_ts
                            valid_candidates.append(c)
                        else:
                            logger.debug("Candidate %s out of window: %s not in [%s, %s]", c.alert_id, c_ts, start_bound, end_bound)

                    retrieved_count = len(valid_candidates)

                    if not valid_candidates:
                        correlation_status = "no_related_events_found"
                    else:
                        # Deterministic ranking: priority rank asc, abs time delta asc, alert_id asc
                        valid_candidates.sort(
                            key=lambda c: (
                                classify_correlation(c, primary_alert)[0],
                                abs((c.timestamp - anchor_ts).total_seconds()),
                                c.alert_id,
                            )
                        )

                        allowed_related = min(bounded_max_related, bounded_max_evidence - 1)
                        selected_candidates = valid_candidates[:allowed_related]
                        truncated_count = max(0, retrieved_count - len(selected_candidates))

                        has_strong_signal = False
                        for idx, rel in enumerate(selected_candidates, start=2):
                            ev_id = f"EV-{idx:02d}"
                            rank, reason = classify_correlation(rel, primary_alert)
                            if rank < 3:
                                has_strong_signal = True
                            item = alert_to_evidence_item(
                                rel,
                                evidence_id=ev_id,
                                is_primary=False,
                                correlation_reason=reason,
                            )
                            items.append(item)

                        if truncated_count > 0 or not has_strong_signal:
                            correlation_status = "partial"
                        else:
                            correlation_status = "enriched"

                except Exception as e:
                    logger.warning(
                        "Failed to query related events from OpenSearch: %s; falling back to single-alert mode",
                        str(e),
                    )
                    correlation_status = "failed_fallback_single_alert"

        # Calculate serialized size and enforce MAX_EVIDENCE_BYTES budget
        total_bytes = 0
        final_items: List[EvidenceItem] = []
        for item in items:
            item_bytes = len(json.dumps(item.model_dump(), default=str).encode("utf-8"))
            if total_bytes + item_bytes > self.settings.MAX_EVIDENCE_BYTES and final_items:
                logger.info(
                    "Truncating evidence package at %d bytes (limit: %d)",
                    total_bytes,
                    self.settings.MAX_EVIDENCE_BYTES,
                )
                truncated_count += len(items) - len(final_items)
                if correlation_status == "enriched":
                    correlation_status = "partial"
                break
            final_items.append(item)
            total_bytes += item_bytes

        included_related = max(0, len(final_items) - 1)

        summary = RelatedEventsSummary(
            correlation_status=correlation_status,
            retrieved_count=retrieved_count,
            included_count=included_related,
            truncated_count=truncated_count,
            window_minutes=bounded_window_mins,
            anchor_timestamp=anchor_ts,
            unsupported_signals=["process_lineage", "command_line"],
        )

        return EvidencePackage(
            package_id=package_id,
            alert_id=primary_alert.alert_id,
            created_at=datetime.now(timezone.utc),
            items=final_items,
            total_events=len(final_items),
            total_bytes=total_bytes,
            redactions_applied=True,
            correlation_status=correlation_status,
            related_events_summary=summary,
        )

    async def _fetch_candidate_alerts(
        self,
        primary_alert: NormalizedAlert,
        window_minutes: int,
        max_to_fetch: int,
    ) -> List[NormalizedAlert]:
        """Bounded search across host, IP, and user dimensions for candidate correlated alerts."""
        half_window = timedelta(minutes=window_minutes / 2.0)
        raw_anchor = primary_alert.timestamp
        if raw_anchor.tzinfo is None:
            anchor_ts = raw_anchor.replace(tzinfo=timezone.utc)
        else:
            anchor_ts = raw_anchor.astimezone(timezone.utc)

        start = anchor_ts - half_window
        end = anchor_ts + half_window

        candidates_map: Dict[str, NormalizedAlert] = {}

        host = (
            primary_alert.agent_name or primary_alert.host_name
            if is_valid_agent(primary_alert.agent_name or primary_alert.host_name)
            else None
        )
        source_ip = primary_alert.source_ip if is_valid_ip(primary_alert.source_ip) else None
        username = primary_alert.username if is_valid_username(primary_alert.username) else None

        # 1. Search by host/agent if verified
        if host:
            alerts_host, _, _ = await self.opensearch.search_alerts(
                start_time=start,
                end_time=end,
                host_name=host,
                page=1,
                page_size=max_to_fetch,
                sort_order="asc",
            )
            for a in alerts_host:
                if a.alert_id != primary_alert.alert_id:
                    candidates_map[a.alert_id] = a

        # 2. Search by source_ip if verified and capacity remains
        if source_ip and len(candidates_map) < max_to_fetch:
            alerts_ip, _, _ = await self.opensearch.search_alerts(
                start_time=start,
                end_time=end,
                source_ip=source_ip,
                page=1,
                page_size=max_to_fetch,
                sort_order="asc",
            )
            for a in alerts_ip:
                if a.alert_id != primary_alert.alert_id:
                    candidates_map[a.alert_id] = a

        # 3. Search by username if verified and capacity remains
        if username and len(candidates_map) < max_to_fetch:
            alerts_user, _, _ = await self.opensearch.search_alerts(
                start_time=start,
                end_time=end,
                username=username,
                page=1,
                page_size=max_to_fetch,
                sort_order="asc",
            )
            for a in alerts_user:
                if a.alert_id != primary_alert.alert_id:
                    candidates_map[a.alert_id] = a

        # 4. If neither host, IP, nor username is known, do bounded time-window query
        if not host and not source_ip and not username:
            alerts_time, _, _ = await self.opensearch.search_alerts(
                start_time=start,
                end_time=end,
                page=1,
                page_size=max_to_fetch,
                sort_order="asc",
            )
            for a in alerts_time:
                if a.alert_id != primary_alert.alert_id:
                    candidates_map[a.alert_id] = a

        return list(candidates_map.values())
