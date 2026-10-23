"""OpenSearch/Wazuh Indexer client providing safe, bounded alert searches."""

import base64
from datetime import datetime, timezone
import ipaddress
import logging
import math
from typing import Any, Dict, List, Optional, Tuple
import httpx

from app.core.config import Settings
from app.core.errors import AppException
from app.core.tls import build_ssl_context
from app.schemas.alert import DataStatus, NormalizedAlert
from app.schemas.error import ErrorCode

logger = logging.getLogger("siem.opensearch_client")


class OpenSearchClient:
    """Read-only client for OpenSearch / Wazuh Indexer alert queries."""

    def __init__(self, settings: Settings, client: Optional[httpx.AsyncClient] = None):
        self.settings = settings
        self.base_url = settings.OPENSEARCH_URL.rstrip("/")
        # Strictly pinned index pattern; callers cannot override
        self.index_pattern = settings.OPENSEARCH_ALERT_INDEX_PATTERN
        self._custom_client = client is not None

        if client is not None:
            self._client = client
        else:
            ssl_context = build_ssl_context(settings.OPENSEARCH_CA_CERT_PATH)
            self._client = httpx.AsyncClient(
                verify=ssl_context,
                timeout=httpx.Timeout(10.0, connect=5.0),
            )

    async def aclose(self) -> None:
        """Close the underlying HTTP client if internally managed."""
        if not self._custom_client and not self._client.is_closed:
            await self._client.aclose()

    def _get_auth_header(self) -> str:
        """Build Basic authentication header from configuration."""
        if not self.settings.is_opensearch_configured():
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="OpenSearch credentials are not configured",
                status_code=500,
            )
        user = self.settings.OPENSEARCH_USERNAME or ""
        pwd = self.settings.OPENSEARCH_PASSWORD.get_secret_value() if self.settings.OPENSEARCH_PASSWORD else ""
        raw = f"{user}:{pwd}".encode("utf-8")
        return f"Basic {base64.b64encode(raw).decode('ascii')}"

    def _normalize_hit(self, hit: Dict[str, Any], retrieved_at: datetime) -> NormalizedAlert:
        """Transform a raw OpenSearch alert document into a canonical NormalizedAlert."""
        warnings: List[str] = []
        source = hit.get("_source", {})
        doc_id = hit.get("_id", "unknown")
        doc_index = hit.get("_index", self.index_pattern)

        # Parse timestamp safely using stdlib
        raw_ts = source.get("timestamp") or source.get("@timestamp")
        if not raw_ts:
            warnings.append("Event timestamp missing; using current UTC time")
            ts = retrieved_at
        else:
            ts = None
            raw_str = str(raw_ts).strip()
            # Direct ISO 8601 parsing (handles Z and offsets in Python 3.11+)
            try:
                parsed = datetime.fromisoformat(raw_str)
                ts = parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except Exception:
                for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
                    try:
                        parsed = datetime.strptime(raw_str, fmt)
                        ts = parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
                        break
                    except Exception:
                        continue

            if ts is None:
                warnings.append(f"Failed to parse timestamp '{raw_ts}'; fallback to retrieved_at")
                ts = retrieved_at

        # Extract rule information
        rule = source.get("rule", {})
        rule_id = str(rule.get("id", "unknown"))
        rule_desc = rule.get("description", "No description provided")
        rule_level = rule.get("level")
        if rule_level is not None:
            try:
                rule_level = int(rule_level)
            except (ValueError, TypeError):
                warnings.append(f"Invalid rule level: {rule_level}")
                rule_level = None

        # Extract agent / host details
        agent = source.get("agent", {})
        agent_id = str(agent.get("id")) if agent.get("id") is not None else None
        agent_name = agent.get("name")
        manager = source.get("manager", {})
        host_name = manager.get("name") or agent_name

        # Extract network/user fields
        data = source.get("data", {})
        src_ip = data.get("srcip") or source.get("srcip")
        dst_ip = data.get("dstip") or source.get("dstip")
        username = data.get("srcuser") or data.get("dstuser") or source.get("srcuser")
        event_type = data.get("type") or source.get("type")

        # Decoder & location
        decoder = source.get("decoder", {})
        decoder_name = decoder.get("name") if isinstance(decoder, dict) else str(decoder) if decoder else None
        location = source.get("location")

        return NormalizedAlert(
            alert_id=doc_id,
            source_system="Wazuh",
            source_index=doc_index,
            timestamp=ts,
            retrieved_at=retrieved_at,
            rule_id=rule_id,
            rule_description=rule_desc,
            rule_level=rule_level,
            agent_id=agent_id,
            agent_name=agent_name,
            host_name=host_name,
            source_ip=str(src_ip) if src_ip else None,
            destination_ip=str(dst_ip) if dst_ip else None,
            username=str(username) if username else None,
            event_type=str(event_type) if event_type else None,
            location=str(location) if location else None,
            decoder_name=decoder_name,
            raw_evidence_ref=f"{doc_index}/{doc_id}",
            normalization_warnings=warnings,
        )

    def _build_search_query(
        self,
        start_time: datetime,
        end_time: datetime,
        severity_min: Optional[int] = None,
        rule_id: Optional[str] = None,
        host_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        page: int = 1,
        page_size: int = 25,
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """Construct safe parameterized OpenSearch query without arbitrary user DSL."""
        start_iso = start_time.astimezone(timezone.utc).isoformat()
        end_iso = end_time.astimezone(timezone.utc).isoformat()

        must_filters: List[Dict[str, Any]] = [
            {"range": {"timestamp": {"gte": start_iso, "lte": end_iso}}}
        ]

        if severity_min is not None:
            must_filters.append({"range": {"rule.level": {"gte": severity_min}}})
        if rule_id:
            must_filters.append({"term": {"rule.id": str(rule_id)}})
        if host_name:
            must_filters.append({"term": {"agent.name": str(host_name)}})
        if source_ip:
            must_filters.append({"term": {"data.srcip": str(source_ip)}})
        if username:
            must_filters.append({"term": {"data.srcuser": str(username)}})

        sort_dir = "asc" if sort_order.lower() == "asc" else "desc"

        return {
            "from": (page - 1) * page_size,
            "size": page_size,
            "sort": [{"timestamp": {"order": sort_dir}}],
            "query": {"bool": {"must": must_filters}},
            "track_total_hits": True,
        }

    async def search_alerts(
        self,
        start_time: datetime,
        end_time: datetime,
        severity_min: Optional[int] = None,
        rule_id: Optional[str] = None,
        host_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        page: int = 1,
        page_size: int = 25,
        sort_order: str = "desc",
    ) -> Tuple[List[NormalizedAlert], int, DataStatus]:
        """Perform a strictly bounded, parameterized alert search.
        
        Guarantees:
        - No arbitrary caller DSL is accepted.
        - Enforces max time window (MAX_QUERY_WINDOW_HOURS).
        - Enforces max page size (MAX_SEARCH_RESULTS).
        """
        # Validate time window
        if start_time > end_time:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="start_time must be earlier than or equal to end_time",
                status_code=400,
            )

        window_seconds = (end_time - start_time).total_seconds()
        max_allowed_seconds = self.settings.MAX_QUERY_WINDOW_HOURS * 3600
        if window_seconds > max_allowed_seconds:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message=f"Query time window exceeds maximum allowable limit of {self.settings.MAX_QUERY_WINDOW_HOURS} hours",
                status_code=400,
            )

        # Validate pagination bounds
        if page < 1:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="page must be >= 1",
                status_code=400,
            )
        if page_size < 1 or page_size > self.settings.MAX_SEARCH_RESULTS:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message=f"page_size must be between 1 and {self.settings.MAX_SEARCH_RESULTS}",
                status_code=400,
            )

        # Validate optional IP address format
        if source_ip:
            try:
                ipaddress.ip_address(source_ip)
            except ValueError:
                raise AppException(
                    code=ErrorCode.VALIDATION_ERROR,
                    message=f"Invalid source_ip format: '{source_ip}'",
                    status_code=400,
                )

        # Validate severity
        if severity_min is not None and not (1 <= severity_min <= 16):
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="severity_min must be an integer between 1 and 16",
                status_code=400,
            )

        query_body = self._build_search_query(
            start_time=start_time,
            end_time=end_time,
            severity_min=severity_min,
            rule_id=rule_id,
            host_name=host_name,
            source_ip=source_ip,
            username=username,
            page=page,
            page_size=page_size,
            sort_order=sort_order,
        )

        retrieved_at = datetime.now(timezone.utc)
        url = f"{self.base_url}/{self.index_pattern}/_search"
        headers = {
            "Authorization": self._get_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            resp = await self._client.post(url, json=query_body, headers=headers)
        except httpx.ConnectError as err:
            logger.error("OpenSearch connection failed: %s", type(err).__name__)
            raise AppException(
                code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                message="Cannot connect to OpenSearch cluster",
                status_code=503,
            ) from err
        except httpx.TimeoutException as err:
            logger.error("OpenSearch request timeout: %s", type(err).__name__)
            raise AppException(
                code=ErrorCode.UPSTREAM_TIMEOUT,
                message="OpenSearch search request timed out",
                status_code=504,
            ) from err
        except Exception as err:
            logger.error("Unexpected OpenSearch error: %s", type(err).__name__)
            raise AppException(
                code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                message="OpenSearch search error",
                status_code=502,
            ) from err

        if resp.status_code == 404:
            # Index does not exist yet (e.g. freshly bootstrapped cluster)
            logger.info("OpenSearch index '%s' not found; returning empty result set", self.index_pattern)
            return [], 0, DataStatus.PARTIAL

        if resp.status_code in (401, 403):
            logger.warning("OpenSearch authentication failed with status %d", resp.status_code)
            raise AppException(
                code=ErrorCode.UNAUTHORIZED if resp.status_code == 401 else ErrorCode.FORBIDDEN,
                message="OpenSearch authentication or authorization failed",
                status_code=resp.status_code,
            )

        if resp.status_code != 200:
            logger.error("OpenSearch returned error status %d", resp.status_code)
            raise AppException(
                code=ErrorCode.INTERNAL_ERROR,
                message="OpenSearch query execution failed",
                status_code=502,
            )

        try:
            data = resp.json()
            hits_data = data.get("hits", {})
            total_raw = hits_data.get("total", {})
            total_count = total_raw.get("value", 0) if isinstance(total_raw, dict) else int(total_raw)
            raw_hits = hits_data.get("hits", [])
        except Exception as err:
            logger.error("Failed to parse OpenSearch response payload: %s", err)
            raise AppException(
                code=ErrorCode.INTERNAL_ERROR,
                message="Malformed OpenSearch response payload",
                status_code=502,
            ) from err

        normalized = [self._normalize_hit(h, retrieved_at) for h in raw_hits]
        return normalized, total_count, DataStatus.FRESH

    async def get_alert_by_id(self, alert_id: str) -> Optional[NormalizedAlert]:
        """Fetch a single alert by its exact stable source document ID."""
        if not alert_id or not alert_id.strip():
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="alert_id must not be empty",
                status_code=400,
            )

        retrieved_at = datetime.now(timezone.utc)
        url = f"{self.base_url}/{self.index_pattern}/_search"
        headers = {
            "Authorization": self._get_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = {
            "query": {"term": {"_id": alert_id.strip()}},
            "size": 1,
        }

        try:
            resp = await self._client.post(url, json=body, headers=headers)
        except httpx.ConnectError as err:
            raise AppException(
                code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                message="Cannot connect to OpenSearch cluster",
                status_code=503,
            ) from err
        except httpx.TimeoutException as err:
            raise AppException(
                code=ErrorCode.UPSTREAM_TIMEOUT,
                message="OpenSearch document request timed out",
                status_code=504,
            ) from err
        except Exception as err:
            raise AppException(
                code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                message="OpenSearch communication error",
                status_code=502,
            ) from err

        if resp.status_code in (401, 403):
            raise AppException(
                code=ErrorCode.UNAUTHORIZED if resp.status_code == 401 else ErrorCode.FORBIDDEN,
                message="OpenSearch authentication failed",
                status_code=resp.status_code,
            )

        if resp.status_code == 404:
            return None

        if resp.status_code != 200:
            raise AppException(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"OpenSearch lookup failed with status {resp.status_code}",
                status_code=502,
            )

        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return None

        return self._normalize_hit(hits[0], retrieved_at)
