import os
from pathlib import Path
import tempfile

# Force isolated temporary test database so tests never create data/siem_history.db
_test_db_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
_test_db_path = Path(_test_db_dir.name) / "test_isolated_history.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_test_db_path.as_posix()}"
os.environ["APP_ENV"] = "test"

# Pre-initialize schema in isolated test database
from sqlalchemy import create_engine
from app.db.base import Base
import app.models.investigation  # noqa: F401
import app.models.audit  # noqa: F401
import app.models.case  # noqa: F401

_sync_engine = create_engine(f"sqlite:///{_test_db_path.as_posix()}")
Base.metadata.create_all(_sync_engine)
_sync_engine.dispose()

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
