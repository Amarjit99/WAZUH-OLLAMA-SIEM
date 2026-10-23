"""FastAPI application entry point for Wazuh + Ollama SIEM backend."""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.api.v1.health import router as root_health_router
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.middleware import CorrelationIdMiddleware
from app.services.ollama_client import OllamaClient
from app.services.opensearch_client import OpenSearchClient
from app.services.wazuh_client import WazuhClient

logger = logging.getLogger("siem")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    )
    logger.info("Starting Wazuh + Ollama SIEM Backend in %s mode", settings.APP_ENV)
    logger.info("Backend listening on %s:%s", settings.APP_HOST, settings.APP_PORT)
    if settings.API_AUTH_REQUIRED and not settings.is_api_auth_configured():
        logger.error(
            "API_AUTH_REQUIRED is True but API_KEY is not configured or empty; "
            "all protected API routes will fail closed (HTTP 500)"
        )

    opensearch_client = OpenSearchClient(settings=settings)
    wazuh_client = WazuhClient(settings=settings)
    ollama_client = OllamaClient(settings=settings)
    app.state.opensearch_client = opensearch_client
    app.state.wazuh_client = wazuh_client
    app.state.ollama_client = ollama_client

    # Initialize persistence service and reconcile orphaned investigations
    from app.services.investigation_persistence_service import InvestigationPersistenceService
    from app.services.retention_service import RetentionService
    from app.db.session import dispose_engine

    persistence_service = InvestigationPersistenceService()
    retention_service = RetentionService(settings=settings)
    app.state.investigation_persistence_service = persistence_service
    app.state.retention_service = retention_service

    from app.services.backup_scheduler_service import BackupSchedulerService
    backup_scheduler_service = BackupSchedulerService(settings=settings)
    app.state.backup_scheduler_service = backup_scheduler_service
    if settings.BACKUP_SCHEDULE_ENABLED:
        backup_scheduler_service.start()

    try:
        reconciled_count = await persistence_service.reconcile_orphaned_at_startup()
        if reconciled_count > 0:
            logger.warning(
                "Startup crash recovery: reconciled %d orphaned investigation(s) with ORPHANED_PROCESS_CRASH",
                reconciled_count,
            )
        else:
            logger.debug("Startup crash recovery: zero orphaned investigations found")
    except Exception as exc:
        logger.error(
            "Startup crash recovery failed: database error during reconciliation: %s",
            str(exc),
            exc_info=True,
        )
        if settings.APP_ENV == "production":
            raise

    try:
        yield
    finally:
        logger.info("Closing backend clients and database engine...")
        if hasattr(app.state, "backup_scheduler_service"):
            await app.state.backup_scheduler_service.stop()
        await opensearch_client.aclose()
        await wazuh_client.aclose()
        await ollama_client.aclose()
        await dispose_engine()
        logger.info("Shutting down Wazuh + Ollama SIEM Backend")


def create_app() -> FastAPI:
    """Application factory for FastAPI server."""
    app = FastAPI(
        title="Wazuh + Ollama SIEM API",
        description="Local AI-assisted security investigation and threat hunting platform backend.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Middleware
    app.add_middleware(CorrelationIdMiddleware)
    settings = get_settings()
    allowed_origins = [o.strip() for o in settings.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Response-Time-Ms"],
    )


    # Register error handlers
    register_error_handlers(app)

    # Mount routers
    app.include_router(api_router)
    app.include_router(root_health_router)  # Also expose /health/live and /health/ready at root

    @app.get("/")
    async def root() -> dict[str, str]:
        """Root endpoint returning service description."""
        return {
            "service": "Wazuh + Ollama SIEM API",
            "version": "0.1.0",
            "docs": "/docs",
        }

    return app


app = create_app()
