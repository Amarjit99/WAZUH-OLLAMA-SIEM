"""API v1 router assembly."""

from fastapi import APIRouter
from app.api.v1.agents import router as agents_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.cases import router as cases_router
from app.api.v1.health import router as health_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.notifications import router as notifications_router

v1_router = APIRouter(prefix="/v1")
v1_router.include_router(health_router)
v1_router.include_router(alerts_router)
v1_router.include_router(investigations_router)
v1_router.include_router(cases_router)
v1_router.include_router(agents_router)
v1_router.include_router(notifications_router)

__all__ = ["v1_router"]


