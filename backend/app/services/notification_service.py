"""Asynchronous webhook notification service for high-severity SOC alert dispatch."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
import httpx

from app.core.config import Settings
from app.schemas.notification import (
    AlertNotificationPayload,
    NotificationTestResponse,
)

logger = logging.getLogger("siem.notification_service")


class NotificationService:
    """Non-blocking notification dispatcher for critical SOC events and webhooks."""

    def __init__(self, settings: Settings, client: Optional[httpx.AsyncClient] = None):
        self.settings = settings
        self._custom_client = client is not None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.ALERT_WEBHOOK_TIMEOUT_SECONDS, connect=3.0)
        )

    async def aclose(self) -> None:
        """Close underlying HTTP client if internally managed."""
        if not self._custom_client and not self._client.is_closed:
            await self._client.aclose()

    @staticmethod
    def _mask_url(url: str) -> str:
        """Safely mask webhook tokens or path secrets from logging."""
        if not url:
            return ""
        parts = url.split("/")
        if len(parts) > 4:
            return f"{parts[0]}//{parts[2]}/{parts[3]}/...[REDACTED]"
        return f"{url[:15]}...[REDACTED]"

    def _format_payload(self, url: str, payload: AlertNotificationPayload) -> Dict[str, Any]:
        """Format notification payload depending on target platform (Discord, Slack, or Generic)."""
        lower_url = url.lower()

        # Discord Webhook format
        if "discord.com/api/webhooks" in lower_url or "discordapp.com/api/webhooks" in lower_url:
            severity_color = 0xE02424 if payload.rule_level >= 10 else 0xF59E0B  # Red or Orange
            return {
                "username": "Wazuh SIEM Alert Guard",
                "embeds": [
                    {
                        "title": f"🚨 High-Severity Alert: Level {payload.rule_level}",
                        "description": payload.rule_description,
                        "color": severity_color,
                        "fields": [
                            {"name": "Rule ID", "value": str(payload.rule_id), "inline": True},
                            {"name": "Severity", "value": f"Level {payload.rule_level}", "inline": True},
                            {"name": "Agent", "value": payload.agent_name or "N/A", "inline": True},
                            {"name": "Source IP", "value": payload.source_ip or "N/A", "inline": True},
                            {"name": "Location", "value": payload.location or "N/A", "inline": True},
                            {"name": "Timestamp (UTC)", "value": payload.timestamp, "inline": False},
                        ],
                        "footer": {"text": "Wazuh + Ollama SIEM Platform"},
                        "url": payload.dashboard_url,
                    }
                ],
            }

        # Slack Webhook format
        if "hooks.slack.com" in lower_url:
            return {
                "text": f"🚨 *[Level {payload.rule_level}]* {payload.rule_description} (Agent: {payload.agent_name or 'N/A'})",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🚨 High-Severity Security Alert — Level {payload.rule_level}",
                            "emoji": True,
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Rule ID:* {payload.rule_id}"},
                            {"type": "mrkdwn", "text": f"*Severity:* Level {payload.rule_level}"},
                            {"type": "mrkdwn", "text": f"*Agent:* {payload.agent_name or 'N/A'}"},
                            {"type": "mrkdwn", "text": f"*Source IP:* {payload.source_ip or 'N/A'}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Description:* {payload.rule_description}"},
                    },
                ],
            }

        # Default: Clean Generic JSON
        return payload.model_dump()

    async def send_alert_notification(self, payload: AlertNotificationPayload) -> bool:
        """Asynchronously dispatch alert webhook. Fail-safe, never raises to disrupt caller."""
        if not self.settings.is_alert_webhook_configured():
            logger.debug("Webhook notification skipped: notifications not configured")
            return False

        if payload.rule_level < self.settings.ALERT_WEBHOOK_MIN_LEVEL:
            logger.debug(
                "Webhook notification skipped: rule_level %d < min_level %d",
                payload.rule_level,
                self.settings.ALERT_WEBHOOK_MIN_LEVEL,
            )
            return False

        target_url = self.settings.ALERT_WEBHOOK_URL.get_secret_value()
        body = self._format_payload(target_url, payload)

        try:
            resp = await self._client.post(
                target_url,
                json=body,
                headers={"Content-Type": "application/json", "User-Agent": "Wazuh-Ollama-SIEM/1.0"},
            )
            if resp.status_code in (200, 204):
                logger.info("Successfully delivered webhook alert for alert_id %s", payload.alert_id)
                return True
            else:
                logger.warning(
                    "Webhook endpoint responded with HTTP %d for target %s",
                    resp.status_code,
                    self._mask_url(target_url),
                )
                return False
        except Exception as err:
            logger.warning(
                "Failed to dispatch webhook alert to %s: %s",
                self._mask_url(target_url),
                type(err).__name__,
            )
            return False

    async def test_webhook(self, override_url: Optional[str] = None) -> NotificationTestResponse:
        """Execute a connectivity test dispatch."""
        target_url = override_url
        if not target_url and self.settings.is_alert_webhook_configured():
            target_url = self.settings.ALERT_WEBHOOK_URL.get_secret_value()

        if not target_url:
            return NotificationTestResponse(
                status="disabled",
                message="No webhook URL is configured. Set ALERT_WEBHOOK_URL in .env or pass a target URL.",
                dispatched_at=datetime.now(timezone.utc),
            )

        test_payload = AlertNotificationPayload(
            event_type="test_notification",
            timestamp=datetime.now(timezone.utc).isoformat(),
            alert_id="test-alert-001",
            rule_id="100001",
            rule_description="Test Security Notification from Wazuh + Ollama SIEM Platform",
            rule_level=12,
            agent_id="000",
            agent_name="wazuh.manager",
            source_ip="127.0.0.1",
            location="system_test",
            dashboard_url="http://127.0.0.1:5174",
        )

        body = self._format_payload(target_url, test_payload)
        masked = self._mask_url(target_url)

        try:
            resp = await self._client.post(
                target_url,
                json=body,
                headers={"Content-Type": "application/json", "User-Agent": "Wazuh-Ollama-SIEM/1.0"},
            )
            if resp.status_code in (200, 204):
                return NotificationTestResponse(
                    status="delivered",
                    message=f"Test notification delivered successfully (HTTP {resp.status_code}).",
                    target_masked=masked,
                    dispatched_at=datetime.now(timezone.utc),
                )
            else:
                return NotificationTestResponse(
                    status="failed",
                    message=f"Endpoint returned unexpected HTTP status code {resp.status_code}.",
                    target_masked=masked,
                    dispatched_at=datetime.now(timezone.utc),
                )
        except Exception as err:
            return NotificationTestResponse(
                status="failed",
                message=f"Network error during delivery attempt: {type(err).__name__}",
                target_masked=masked,
                dispatched_at=datetime.now(timezone.utc),
            )
