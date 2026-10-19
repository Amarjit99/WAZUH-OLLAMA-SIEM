"""Test fixtures for FastAPI backend."""

import pytest
from fastapi.testclient import TestClient
from app.core.config import Settings
from app.main import app


@pytest.fixture
def client() -> TestClient:
    """Synchronous test client fixture."""
    return TestClient(app)


@pytest.fixture
def custom_settings() -> Settings:
    """Fixture providing clean test settings."""
    return Settings(
        APP_ENV="test",
        WAZUH_API_URL="https://127.0.0.1:55000",
        WAZUH_API_USERNAME=None,
        WAZUH_API_PASSWORD=None,
        OPENSEARCH_URL="https://127.0.0.1:9200",
        OPENSEARCH_USERNAME=None,
        OPENSEARCH_PASSWORD=None,
        OLLAMA_BASE_URL="http://127.0.0.1:11434",
        OLLAMA_MODEL="",
    )
