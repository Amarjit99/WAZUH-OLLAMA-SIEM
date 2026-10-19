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
    yield
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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Local development; tighten in security hardening phase
        allow_credentials=True,
        allow_methods=["*"],
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
