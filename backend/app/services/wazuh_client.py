"""Wazuh Manager API Client providing authenticated, read-only telemetry access."""

import asyncio
import base64
import logging
import time
from typing import Any, Dict, Optional
import httpx

from app.core.config import Settings
from app.core.errors import AppException
from app.core.tls import build_ssl_context
from app.schemas.error import ErrorCode

logger = logging.getLogger("siem.wazuh_client")


class WazuhClient:
    """Read-only client for Wazuh Manager REST API (v4.x)."""

    def __init__(self, settings: Settings, client: Optional[httpx.AsyncClient] = None):
        self.settings = settings
        self.base_url = settings.WAZUH_API_URL.rstrip("/")
        self._custom_client = client is not None
        
        if client is not None:
            self._client = client
        else:
            ssl_context = build_ssl_context(settings.WAZUH_CA_CERT_PATH)
            self._client = httpx.AsyncClient(
                verify=ssl_context,
                timeout=httpx.Timeout(10.0, connect=5.0),
            )

        self._token: Optional[str] = None
        self._token_expiry: float = 0.0
        self._auth_lock = asyncio.Lock()

    async def aclose(self) -> None:
        """Close the underlying HTTP client if internally managed."""
        if not self._custom_client and not self._client.is_closed:
            await self._client.aclose()

    async def authenticate(self, force_refresh: bool = False) -> str:
        """Acquire or refresh in-memory JWT token safely under concurrency."""
        now = time.monotonic()
        if not force_refresh and self._token and now < self._token_expiry - 60.0:
            return self._token

        async with self._auth_lock:
            # Re-check inside critical section
            now = time.monotonic()
            if not force_refresh and self._token and now < self._token_expiry - 60.0:
                return self._token

            if not self.settings.is_wazuh_configured():
                raise AppException(
                    code=ErrorCode.VALIDATION_ERROR,
                    message="Wazuh API credentials are not configured",
                    status_code=500,
                )

            username = self.settings.WAZUH_API_USERNAME or ""
            password = self.settings.WAZUH_API_PASSWORD.get_secret_value() if self.settings.WAZUH_API_PASSWORD else ""
            cred_bytes = f"{username}:{password}".encode("utf-8")
            auth_header = f"Basic {base64.b64encode(cred_bytes).decode('ascii')}"

            auth_url = f"{self.base_url}/security/user/authenticate"
            try:
                resp = await self._client.post(
                    auth_url,
                    headers={"Authorization": auth_header},
                )
            except httpx.ConnectError as err:
                logger.error("Wazuh connection error during authentication: %s", type(err).__name__)
                raise AppException(
                    code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                    message="Cannot connect to Wazuh Manager API",
                    status_code=503,
                ) from err
            except httpx.TimeoutException as err:
                logger.error("Wazuh timeout during authentication: %s", type(err).__name__)
                raise AppException(
                    code=ErrorCode.UPSTREAM_TIMEOUT,
                    message="Wazuh Manager API authentication timed out",
                    status_code=504,
                ) from err
            except Exception as err:
                logger.error("Unexpected error during Wazuh authentication: %s", type(err).__name__)
                raise AppException(
                    code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                    message="Wazuh Manager API TLS handshake or connection failed",
                    status_code=503,
                ) from err

            if resp.status_code == 401:
                logger.warning("Wazuh authentication rejected (HTTP 401)")
                raise AppException(
                    code=ErrorCode.UNAUTHORIZED,
                    message="Invalid Wazuh API credentials",
                    status_code=401,
                )
            if resp.status_code != 200:
                logger.error("Wazuh authentication failed with status %d", resp.status_code)
                raise AppException(
                    code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                    message=f"Wazuh API authentication returned HTTP {resp.status_code}",
                    status_code=502,
                )

            try:
                payload = resp.json()
                token = payload.get("data", {}).get("token")
                if not token:
                    raise ValueError("JWT token missing from response payload")
            except Exception as err:
                logger.error("Failed to parse Wazuh authentication token: %s", err)
                raise AppException(
                    code=ErrorCode.INTERNAL_ERROR,
                    message="Malformed authentication response from Wazuh API",
                    status_code=502,
                ) from err

            self._token = token
            # Default Wazuh JWT expiration is 900 seconds (15 minutes)
            self._token_expiry = time.monotonic() + 900.0
            return self._token

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute an authenticated read-only HTTP request against Wazuh API with token auto-retry."""
        token = await self.authenticate()
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        try:
            resp = await self._client.request(method, url, headers=headers, params=params)
            
            # If token expired on server side, retry once with fresh authentication
            if resp.status_code == 401:
                logger.info("Wazuh token rejected (HTTP 401); re-authenticating once...")
                token = await self.authenticate(force_refresh=True)
                headers["Authorization"] = f"Bearer {token}"
                resp = await self._client.request(method, url, headers=headers, params=params)

            if resp.status_code == 401:
                raise AppException(
                    code=ErrorCode.UNAUTHORIZED,
                    message="Wazuh API session unauthorized",
                    status_code=401,
                )
            if resp.status_code == 403:
                raise AppException(
                    code=ErrorCode.FORBIDDEN,
                    message="Access to Wazuh API resource forbidden",
                    status_code=403,
                )
            if resp.status_code == 404:
                raise AppException(
                    code=ErrorCode.NOT_FOUND,
                    message="Wazuh API resource not found",
                    status_code=404,
                )
            if resp.status_code != 200:
                raise AppException(
                    code=ErrorCode.INTERNAL_ERROR,
                    message=f"Wazuh API request failed with status {resp.status_code}",
                    status_code=502,
                )

            return resp.json()

        except AppException:
            raise
        except httpx.ConnectError as err:
            logger.error("Wazuh API connection failure: %s", type(err).__name__)
            raise AppException(
                code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                message="Cannot connect to Wazuh Manager API",
                status_code=503,
            ) from err
        except httpx.TimeoutException as err:
            logger.error("Wazuh API request timeout: %s", type(err).__name__)
            raise AppException(
                code=ErrorCode.UPSTREAM_TIMEOUT,
                message="Wazuh Manager API request timed out",
                status_code=504,
            ) from err
        except Exception as err:
            logger.error("Unexpected Wazuh API error: %s", type(err).__name__)
            raise AppException(
                code=ErrorCode.DEPENDENCY_UNAVAILABLE,
                message="Wazuh Manager API communication error",
                status_code=502,
            ) from err

    async def get_api_info(self) -> Dict[str, Any]:
        """Retrieve Wazuh API version and basic information (read-only)."""
        return await self._request("GET", "/")

    async def get_manager_status(self) -> Dict[str, Any]:
        """Retrieve Wazuh Manager daemon operational statuses (read-only)."""
        return await self._request("GET", "/manager/status")

    async def get_agents(self, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
        """Retrieve registered Wazuh agents list (read-only, bounded)."""
        limit = min(max(1, limit), 100)
        offset = max(0, offset)
        return await self._request("GET", "/agents", params={"limit": limit, "offset": offset})
