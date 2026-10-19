"""Unit tests for request correlation and error envelopes."""

import uuid
from fastapi.testclient import TestClient


def test_correlation_id_generated(client: TestClient):
    """Verify that every response receives an X-Request-ID header."""
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    req_id = response.headers.get("X-Request-ID")
    assert req_id is not None
    # Must be valid UUID format
    parsed = uuid.UUID(req_id)
    assert str(parsed) == req_id


def test_correlation_id_propagated(client: TestClient):
    """Verify that an incoming X-Request-ID is preserved and returned."""
    custom_id = "test-correlation-id-12345"
    response = client.get("/api/v1/health/live", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_id


def test_not_found_error_envelope(client: TestClient):
    """Verify 404 conforms strictly to specs/API_CONTRACT.md error envelope."""
    response = client.get("/api/v1/nonexistent-endpoint")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert "message" in data["error"]
    assert "request_id" in data["error"]
