"""Unit tests for webhook notification service and notification endpoints."""

from datetime import datetime, timezone
import pytest
from httpx import ASGITransport, AsyncClient, Response
from pydantic import SecretStr
from unittest.mock import AsyncMock, MagicMock

from app.core.config import Settings
from app.main import create_app
from app.schemas.notification import AlertNotificationPayload
from app.services.notification_service import NotificationService


@pytest.fixture
def base_alert_payload():
    return AlertNotificationPayload(
        event_type="high_severity_alert",
        timestamp="2026-10-23T15:22:37.509Z",
        alert_id="vG9baaEBafEQfFZDe1H0",
        rule_id="521",
        rule_description="Possible kernel level rootkit",
        rule_level=11,
        agent_id="000",
        agent_name="wazuh.manager",
        source_ip=None,
        location="rootcheck",
        dashboard_url="http://127.0.0.1:5174",
    )


@pytest.mark.asyncio
async def test_notification_disabled_no_op(base_alert_payload):
    """When notifications are disabled, send_alert_notification returns False and does not post."""
    settings = Settings(NOTIFICATIONS_ENABLED=False, ALERT_WEBHOOK_URL=None)
    mock_http = MagicMock()
    mock_http.post = AsyncMock()

    service = NotificationService(settings=settings, client=mock_http)
    result = await service.send_alert_notification(base_alert_payload)

    assert result is False
    mock_http.post.assert_not_called()


@pytest.mark.asyncio
async def test_notification_skips_low_severity(base_alert_payload):
    """When rule_level is lower than ALERT_WEBHOOK_MIN_LEVEL, notification is skipped."""
    settings = Settings(
        NOTIFICATIONS_ENABLED=True,
        ALERT_WEBHOOK_URL=SecretStr("https://webhook.site/test-uuid"),
        ALERT_WEBHOOK_MIN_LEVEL=12,
    )
    mock_http = MagicMock()
    mock_http.post = AsyncMock()

    service = NotificationService(settings=settings, client=mock_http)
    # base_alert_payload has rule_level=11 < 12
    result = await service.send_alert_notification(base_alert_payload)

    assert result is False
    mock_http.post.assert_not_called()


@pytest.mark.asyncio
async def test_notification_successful_generic_dispatch(base_alert_payload):
    """When enabled and above threshold, generic payload is dispatched via HTTP POST."""
    settings = Settings(
        NOTIFICATIONS_ENABLED=True,
        ALERT_WEBHOOK_URL=SecretStr("https://webhook.site/test-uuid"),
        ALERT_WEBHOOK_MIN_LEVEL=10,
    )
    mock_http = MagicMock()
    mock_http.post = AsyncMock(return_value=Response(status_code=200))

    service = NotificationService(settings=settings, client=mock_http)
    result = await service.send_alert_notification(base_alert_payload)

    assert result is True
    mock_http.post.assert_awaited_once()
    called_args, called_kwargs = mock_http.post.call_args
    assert called_args[0] == "https://webhook.site/test-uuid"
    assert called_kwargs["json"]["alert_id"] == "vG9baaEBafEQfFZDe1H0"
    assert called_kwargs["json"]["rule_level"] == 11


@pytest.mark.asyncio
async def test_notification_discord_formatting(base_alert_payload):
    """When target URL is Discord, formats payload with Discord embeds."""
    settings = Settings(
        NOTIFICATIONS_ENABLED=True,
        ALERT_WEBHOOK_URL=SecretStr("https://discord.com/api/webhooks/123/xyz"),
        ALERT_WEBHOOK_MIN_LEVEL=10,
    )
    mock_http = MagicMock()
    mock_http.post = AsyncMock(return_value=Response(status_code=204))

    service = NotificationService(settings=settings, client=mock_http)
    result = await service.send_alert_notification(base_alert_payload)

    assert result is True
    called_kwargs = mock_http.post.call_args[1]
    json_data = called_kwargs["json"]
    assert "embeds" in json_data
    assert len(json_data["embeds"]) == 1
    assert "Possible kernel level rootkit" in json_data["embeds"][0]["description"]


@pytest.mark.asyncio
async def test_notification_slack_formatting(base_alert_payload):
    """When target URL is Slack, formats payload with Slack mrkdwn blocks."""
    settings = Settings(
        NOTIFICATIONS_ENABLED=True,
        ALERT_WEBHOOK_URL=SecretStr("https://hooks.slack.com/services/T00/B00/X00"),
        ALERT_WEBHOOK_MIN_LEVEL=10,
    )
    mock_http = MagicMock()
    mock_http.post = AsyncMock(return_value=Response(status_code=200))

    service = NotificationService(settings=settings, client=mock_http)
    result = await service.send_alert_notification(base_alert_payload)

    assert result is True
    called_kwargs = mock_http.post.call_args[1]
    json_data = called_kwargs["json"]
    assert "blocks" in json_data
    assert "text" in json_data


@pytest.mark.asyncio
async def test_notification_dispatch_failure_does_not_raise(base_alert_payload):
    """Network errors or 500 responses return False and do not crash the caller."""
    settings = Settings(
        NOTIFICATIONS_ENABLED=True,
        ALERT_WEBHOOK_URL=SecretStr("https://webhook.site/test-uuid"),
        ALERT_WEBHOOK_MIN_LEVEL=10,
    )
    mock_http = MagicMock()
    mock_http.post = AsyncMock(side_effect=Exception("Connection refused"))

    service = NotificationService(settings=settings, client=mock_http)
    result = await service.send_alert_notification(base_alert_payload)

    assert result is False


@pytest.mark.asyncio
async def test_test_webhook_endpoint_disabled():
    """POST /api/v1/notifications/test returns status='disabled' when not configured."""
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.post("/api/v1/notifications/test", json={})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "disabled"


@pytest.mark.asyncio
async def test_test_webhook_endpoint_override():
    """POST /api/v1/notifications/test delivers test message to override URL."""
    mock_service = MagicMock(spec=NotificationService)
    from app.schemas.notification import NotificationTestResponse
    mock_service.test_webhook = AsyncMock(
        return_value=NotificationTestResponse(
            status="delivered",
            message="Test notification delivered successfully (HTTP 200).",
            target_masked="https://webhook.site/...[REDACTED]",
            dispatched_at=datetime.now(timezone.utc),
        )
    )

    app = create_app()
    app.state.notification_service = mock_service

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.post(
            "/api/v1/notifications/test",
            json={"webhook_url": "https://webhook.site/custom-override"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "delivered"
    assert "Test notification delivered successfully" in data["message"]
    mock_service.test_webhook.assert_awaited_once_with(override_url="https://webhook.site/custom-override")
