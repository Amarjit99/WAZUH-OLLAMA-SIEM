"""Reusable FastAPI dependency providers for clients and services."""

from fastapi import Depends, Request

from app.core.config import Settings, get_settings
from app.services.evidence_service import EvidenceService
from app.services.ollama_client import OllamaClient
from app.services.opensearch_client import OpenSearchClient
from app.services.wazuh_client import WazuhClient


def get_opensearch_client(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> OpenSearchClient:
    """Dependency provider for OpenSearchClient, reusing app-state instance when available."""
    client = getattr(request.app.state, "opensearch_client", None)
    if client is not None:
        return client
    return OpenSearchClient(settings=settings)


def get_wazuh_client(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> WazuhClient:
    """Dependency provider for WazuhClient, reusing app-state instance when available."""
    client = getattr(request.app.state, "wazuh_client", None)
    if client is not None:
        return client
    return WazuhClient(settings=settings)


def get_ollama_client(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> OllamaClient:
    """Dependency provider for OllamaClient, reusing app-state instance when available."""
    client = getattr(request.app.state, "ollama_client", None)
    if client is not None:
        return client
    return OllamaClient(settings=settings)


def get_evidence_service(
    opensearch: OpenSearchClient = Depends(get_opensearch_client),
    settings: Settings = Depends(get_settings),
) -> EvidenceService:
    """Dependency provider for EvidenceService."""
    return EvidenceService(opensearch=opensearch, settings=settings)


from app.services.investigation_persistence_service import InvestigationPersistenceService


def get_investigation_persistence_service(
    request: Request,
) -> InvestigationPersistenceService:
    """Dependency provider for InvestigationPersistenceService, reusing app-state instance when available."""
    service = getattr(request.app.state, "investigation_persistence_service", None)
    if service is not None:
        return service
    return InvestigationPersistenceService()


from app.services.retention_service import RetentionService


def get_retention_service(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> RetentionService:
    """Dependency provider for RetentionService, reusing app-state instance when available."""
    service = getattr(request.app.state, "retention_service", None)
    if service is not None:
        return service
    return RetentionService(settings=settings)


from app.repositories.case_repository import CaseRepository


def get_case_repository() -> CaseRepository:
    """Dependency provider for CaseRepository."""
    return CaseRepository()




import secrets
from typing import Optional
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.core.errors import AppException
from app.schemas.error import ErrorCode

_bearer_scheme = HTTPBearer(auto_error=False)


def verify_api_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> bool:
    """Validate API caller credentials if configured.

    - Default development mode (API_AUTH_REQUIRED=False, API_KEY=None): permits access on loopback.
    - If API_AUTH_REQUIRED=True and API_KEY missing/whitespace: fails closed (500).
    - If API_KEY configured: strictly enforces matching Bearer token using constant-time comparison (401 on failure).
    """
    if not settings.API_AUTH_REQUIRED and not settings.API_KEY:
        return True

    expected_key = settings.API_KEY.get_secret_value().strip() if settings.API_KEY else None
    if not expected_key:
        if settings.API_AUTH_REQUIRED:
            raise AppException(
                code=ErrorCode.INTERNAL_ERROR,
                message="API authentication is required but no valid non-empty API_KEY is configured on the server",
                status_code=500,
            )
        return True

    if not credentials or not credentials.credentials:
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="Unauthorized: valid API token required",
            status_code=401,
        )

    # Constant-time comparison to prevent timing side-channel attacks
    if not secrets.compare_digest(credentials.credentials.strip(), expected_key):
        raise AppException(
            code=ErrorCode.VALIDATION_ERROR,
            message="Unauthorized: valid API token required",
            status_code=401,
        )
    return True
