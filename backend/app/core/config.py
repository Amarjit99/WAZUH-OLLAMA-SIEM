"""Application configuration management using Pydantic Settings."""

from typing import Optional
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General
    APP_ENV: str = Field(default="development", description="Application environment")
    APP_HOST: str = Field(default="127.0.0.1", description="Server bind host")
    APP_PORT: int = Field(default=8001, description="Server bind port")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")

    # Wazuh API
    WAZUH_API_URL: str = Field(
        default="https://127.0.0.1:55000",
        description="Wazuh Manager API base URL",
    )
    WAZUH_API_USERNAME: Optional[str] = Field(default=None, description="Wazuh API username")
    WAZUH_API_PASSWORD: Optional[SecretStr] = Field(default=None, description="Wazuh API password")
    WAZUH_CA_CERT_PATH: Optional[str] = Field(default=None, description="Path to Wazuh TLS CA certificate")

    # Wazuh Indexer / OpenSearch
    OPENSEARCH_URL: str = Field(
        default="https://127.0.0.1:9200",
        description="Wazuh Indexer / OpenSearch base URL",
    )
    OPENSEARCH_USERNAME: Optional[str] = Field(default=None, description="OpenSearch username")
    OPENSEARCH_PASSWORD: Optional[SecretStr] = Field(default=None, description="OpenSearch password")
    OPENSEARCH_CA_CERT_PATH: Optional[str] = Field(default=None, description="Path to OpenSearch TLS CA cert")
    OPENSEARCH_ALERT_INDEX_PATTERN: str = Field(
        default="wazuh-alerts-*",
        description="Index pattern for security alerts",
    )

    # Ollama
    OLLAMA_BASE_URL: str = Field(
        default="http://127.0.0.1:11434",
        description="Ollama local API base URL",
    )
    OLLAMA_MODEL: str = Field(
        default="",
        description="Target installed model tag",
    )
    OLLAMA_TIMEOUT_SECONDS: int = Field(default=60, description="Ollama request timeout in seconds")
    OLLAMA_MAX_CONCURRENCY: int = Field(default=1, description="Max concurrent Ollama queries")

    # Safety and limits
    MAX_QUERY_WINDOW_HOURS: int = Field(default=24, description="Maximum query time window in hours")
    MAX_SEARCH_RESULTS: int = Field(default=100, description="Maximum search results per page")
    MAX_EVIDENCE_EVENTS: int = Field(default=50, description="Maximum evidence events sent to LLM")
    MAX_EVIDENCE_BYTES: int = Field(default=50000, description="Maximum evidence size in bytes")
    ENABLE_DEMO_FIXTURES: bool = Field(
        default=False,
        description="Strictly development/demo fixtures flag. Must be false in production.",
    )

    # Optional persistence & notifications
    DATABASE_URL: Optional[SecretStr] = None
    QUEUE_URL: Optional[SecretStr] = None
    NOTIFICATIONS_ENABLED: bool = False
    TELEGRAM_ENABLED: bool = False

    def is_wazuh_configured(self) -> bool:
        """Check if Wazuh API credentials are configured."""
        return bool(self.WAZUH_API_USERNAME and self.WAZUH_API_PASSWORD)

    def is_opensearch_configured(self) -> bool:
        """Check if OpenSearch credentials are configured."""
        return bool(self.OPENSEARCH_USERNAME and self.OPENSEARCH_PASSWORD)

    def is_ollama_configured(self) -> bool:
        """Check if Ollama model is configured."""
        return bool(self.OLLAMA_MODEL and self.OLLAMA_MODEL.strip())


# Cached singleton instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Retrieve global cached settings."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
