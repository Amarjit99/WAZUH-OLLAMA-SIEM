"""Health service for genuine dependency readiness checks adhering to FR-002, FR-005."""

import logging
import time
from typing import Dict, Tuple
import httpx

from app.core.config import Settings
from app.core.tls import build_ssl_context
from app.schemas.health import DependencyHealth, DependencyStatus, ServiceStatus

logger = logging.getLogger("siem.health")


class HealthService:
    """Service to probe upstream integrations truthfully."""

    def __init__(self, settings: Settings):
        self.settings = settings

    async def check_wazuh(self) -> DependencyHealth:
        """Probe Wazuh API availability and authentication with TLS verification."""
        if not self.settings.is_wazuh_configured():
            return DependencyHealth(
                status=DependencyStatus.NOT_CONFIGURED,
                message="Wazuh API credentials are not configured",
            )

        start_time = time.perf_counter()
        try:
            ssl_context = build_ssl_context(self.settings.WAZUH_CA_CERT_PATH)
            user = self.settings.WAZUH_API_USERNAME or ""
            pwd = self.settings.WAZUH_API_PASSWORD.get_secret_value() if self.settings.WAZUH_API_PASSWORD else ""

            async with httpx.AsyncClient(verify=ssl_context, timeout=httpx.Timeout(3.0, connect=2.0)) as client:
                resp = await client.post(
                    f"{self.settings.WAZUH_API_URL.rstrip('/')}/security/user/authenticate",
                    auth=(user, pwd),
                )
                latency_ms = (time.perf_counter() - start_time) * 1000.0

                if resp.status_code == 200:
                    return DependencyHealth(
                        status=DependencyStatus.CONNECTED,
                        message="Wazuh API authenticated and operational (TLS verified)",
                        latency_ms=round(latency_ms, 2),
                    )
                if resp.status_code == 401:
                    return DependencyHealth(
                        status=DependencyStatus.DEGRADED,
                        message="Wazuh API endpoint reachable but credentials rejected",
                        latency_ms=round(latency_ms, 2),
                    )
                return DependencyHealth(
                    status=DependencyStatus.DEGRADED,
                    message=f"Wazuh API returned unexpected status {resp.status_code}",
                    latency_ms=round(latency_ms, 2),
                )
        except httpx.ConnectError:
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="Cannot connect to Wazuh API (connection refused)",
            )
        except httpx.TimeoutException:
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="Wazuh API request timed out",
            )
        except Exception as err:
            logger.debug("Wazuh health check failure: %s", type(err).__name__)
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="Wazuh API unavailable or TLS verification failed",
            )

    async def check_opensearch(self) -> DependencyHealth:
        """Probe OpenSearch/Wazuh Indexer availability and authentication with TLS verification."""
        if not self.settings.is_opensearch_configured():
            return DependencyHealth(
                status=DependencyStatus.NOT_CONFIGURED,
                message="OpenSearch credentials are not configured",
            )

        start_time = time.perf_counter()
        try:
            ssl_context = build_ssl_context(self.settings.OPENSEARCH_CA_CERT_PATH)
            user = self.settings.OPENSEARCH_USERNAME or ""
            pwd = self.settings.OPENSEARCH_PASSWORD.get_secret_value() if self.settings.OPENSEARCH_PASSWORD else ""

            async with httpx.AsyncClient(verify=ssl_context, timeout=httpx.Timeout(3.0, connect=2.0)) as client:
                resp = await client.get(
                    f"{self.settings.OPENSEARCH_URL.rstrip('/')}/",
                    auth=(user, pwd),
                )
                latency_ms = (time.perf_counter() - start_time) * 1000.0

                if resp.status_code == 200:
                    return DependencyHealth(
                        status=DependencyStatus.CONNECTED,
                        message="OpenSearch cluster authenticated and operational (TLS verified)",
                        latency_ms=round(latency_ms, 2),
                    )
                if resp.status_code in (401, 403):
                    return DependencyHealth(
                        status=DependencyStatus.DEGRADED,
                        message="OpenSearch cluster reachable but credentials rejected",
                        latency_ms=round(latency_ms, 2),
                    )
                return DependencyHealth(
                    status=DependencyStatus.DEGRADED,
                    message=f"OpenSearch returned status {resp.status_code}",
                    latency_ms=round(latency_ms, 2),
                )
        except httpx.ConnectError:
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="Cannot connect to OpenSearch (connection refused)",
            )
        except httpx.TimeoutException:
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="OpenSearch request timed out",
            )
        except Exception as err:
            logger.debug("OpenSearch health check failure: %s", type(err).__name__)
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="OpenSearch unavailable or TLS verification failed",
            )

    async def check_ollama(self) -> DependencyHealth:
        """Probe local Ollama inference service."""
        if not self.settings.is_ollama_configured():
            return DependencyHealth(
                status=DependencyStatus.NOT_CONFIGURED,
                message="Ollama model is not configured (OLLAMA_MODEL is empty)",
            )

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self.settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags")
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("name") for m in data.get("models", [])]
                    model_found = any(self.settings.OLLAMA_MODEL in m for m in models)
                    if model_found:
                        return DependencyHealth(
                            status=DependencyStatus.CONNECTED,
                            message=f"Ollama running with model '{self.settings.OLLAMA_MODEL}' available",
                            latency_ms=round(latency_ms, 2),
                        )
                    return DependencyHealth(
                        status=DependencyStatus.DEGRADED,
                        message=f"Ollama running, but target model '{self.settings.OLLAMA_MODEL}' not found in installed models",
                        latency_ms=round(latency_ms, 2),
                    )
                return DependencyHealth(
                    status=DependencyStatus.DEGRADED,
                    message=f"Ollama API returned status {resp.status_code}",
                    latency_ms=round(latency_ms, 2),
                )
        except httpx.ConnectError:
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="Cannot connect to local Ollama service (daemon not running)",
            )
        except httpx.TimeoutException:
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="Ollama service timed out",
            )
        except Exception as err:
            logger.debug("Ollama health check failure: %s", str(err))
            return DependencyHealth(
                status=DependencyStatus.UNAVAILABLE,
                message="Ollama check failed",
            )

    async def check_all(self) -> Tuple[ServiceStatus, Dict[str, DependencyHealth]]:
        """Run all readiness checks and compute overall service status."""
        wazuh_health = await self.check_wazuh()
        opensearch_health = await self.check_opensearch()
        ollama_health = await self.check_ollama()

        deps = {
            "wazuh_api": wazuh_health,
            "opensearch": opensearch_health,
            "ollama": ollama_health,
        }

        # Overall status calculation
        statuses = [d.status for d in deps.values()]
        if any(s == DependencyStatus.UNAVAILABLE for s in statuses):
            overall = ServiceStatus.UNAVAILABLE
        elif any(s in (DependencyStatus.DEGRADED, DependencyStatus.NOT_CONFIGURED) for s in statuses):
            overall = ServiceStatus.DEGRADED
        else:
            overall = ServiceStatus.OK

        return overall, deps
