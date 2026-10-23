"""SOC alert notification and webhook testing API endpoints."""

import logging
from fastapi import APIRouter, Depends

from app.api.deps import get_notification_service, verify_api_auth
from app.schemas.notification import (
    NotificationTestRequest,
    NotificationTestResponse,
)
from app.services.notification_service import NotificationService

logger = logging.getLogger("siem.api.notifications")
router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.post("/test", response_model=NotificationTestResponse, summary="Test alert webhook delivery")
async def test_notification_webhook(
    request: NotificationTestRequest,
    notification_service: NotificationService = Depends(get_notification_service),
    _authorized: bool = Depends(verify_api_auth),
) -> NotificationTestResponse:
    """Send a controlled test security alert notification to the configured or supplied webhook URL."""
    return await notification_service.test_webhook(override_url=request.webhook_url)
