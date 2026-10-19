"""Unit tests for configuration and secret handling."""

from pydantic import SecretStr
from app.core.config import Settings


def test_settings_default_values():
    """Verify settings defaults are safe and unconfigured initially."""
    settings = Settings()
    assert settings.APP_ENV in ("development", "test", "production")
    assert isinstance(settings.MAX_QUERY_WINDOW_HOURS, int)
    assert settings.MAX_QUERY_WINDOW_HOURS > 0
    assert settings.ENABLE_DEMO_FIXTURES is False


def test_secrets_are_masked():
    """Verify passwords are treated as SecretStr and not leaked in raw strings."""
    settings = Settings(
        WAZUH_API_PASSWORD=SecretStr("super_secret_wazuh_pass"),
        OPENSEARCH_PASSWORD=SecretStr("super_secret_opensearch_pass"),
    )
    # String representation must not expose raw value
    assert "super_secret_wazuh_pass" not in str(settings.WAZUH_API_PASSWORD)
    assert "super_secret_opensearch_pass" not in str(settings.OPENSEARCH_PASSWORD)
    assert settings.WAZUH_API_PASSWORD.get_secret_value() == "super_secret_wazuh_pass"


def test_configuration_detection_helpers():
    """Test helper predicates for detecting configured services."""
    unconfigured = Settings(
        WAZUH_API_USERNAME=None,
        WAZUH_API_PASSWORD=None,
        OPENSEARCH_USERNAME=None,
        OPENSEARCH_PASSWORD=None,
        OLLAMA_MODEL="",
    )
    assert unconfigured.is_wazuh_configured() is False
    assert unconfigured.is_opensearch_configured() is False
    assert unconfigured.is_ollama_configured() is False

    configured = Settings(
        WAZUH_API_USERNAME="wazuh_user",
        WAZUH_API_PASSWORD=SecretStr("wazuh_pass"),
        OPENSEARCH_USERNAME="admin",
        OPENSEARCH_PASSWORD=SecretStr("admin_pass"),
        OLLAMA_MODEL="llama3.2",
    )
    assert configured.is_wazuh_configured() is True
    assert configured.is_opensearch_configured() is True
    assert configured.is_ollama_configured() is True
