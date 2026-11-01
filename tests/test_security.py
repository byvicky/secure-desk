from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from securedesk import database, security
from securedesk.main import app
from securedesk.security import RateLimiter, redact_sensitive_data


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "settings", SimpleNamespace(database=str(tmp_path / "auth.db")))
    monkeypatch.setattr(security, "settings", SimpleNamespace(production=True, api_key="test-secret"))
    with TestClient(app) as test_client:
        yield test_client


def test_api_key_required_and_validated(client):
    assert client.get("/api/tickets").status_code == 401
    assert client.get("/api/tickets", headers={"Authorization": "Bearer wrong"}).status_code == 401
    response = client.get("/api/tickets", headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 200


def test_redaction_masks_common_identifiers():
    result = redact_sensitive_data("email ana@example.com CPF 123.456.789-00")
    assert "ana@example.com" not in result
    assert "123.456.789-00" not in result
    assert "[EMAIL REDIGIDO]" in result
    assert "[CPF REDIGIDO]" in result


def test_rate_limiter_enforces_window(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("securedesk.security.time.monotonic", lambda: clock[0])
    limiter = RateLimiter(limit=2, window_seconds=60)
    assert limiter.check("client")
    assert limiter.check("client")
    assert not limiter.check("client")
    clock[0] += 61
    assert limiter.check("client")
