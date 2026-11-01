from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from securedesk import database, security
from securedesk.main import app
from securedesk.security import RateLimiter, hash_password, redact_sensitive_data, verify_password


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "settings", SimpleNamespace(database=str(tmp_path / "auth.db")))
    monkeypatch.setattr(security, "settings", SimpleNamespace(production=True, api_key="test-secret", web_password=""))
    with TestClient(app) as test_client:
        yield test_client


def test_api_key_required_and_validated(client):
    assert client.get("/api/tickets").status_code == 401
    assert client.get("/api/tickets", headers={"Authorization": "Bearer wrong"}).status_code == 401
    response = client.get("/api/tickets", headers={"Authorization": "Bearer test-secret"})
    assert response.status_code == 200


def test_password_hash_is_salted_and_verifiable():
    first = hash_password("a-very-strong-password")
    second = hash_password("a-very-strong-password")
    assert first != second
    assert verify_password("a-very-strong-password", first)
    assert not verify_password("wrong-password", first)
    assert not verify_password("password", "invalid")


def test_individual_login_and_admin_user_management(client):
    database.create_user("admin-user", hash_password("admin-password-123"), "admin")
    response = client.post("/api/login", json={
        "username": "admin-user", "password": "admin-password-123"
    })
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"

    created = client.post("/api/users", json={
        "username": "support-agent", "password": "agent-password-123", "role": "agent"
    })
    assert created.status_code == 201
    assert created.json()["username"] == "support-agent"
    assert "password_hash" not in created.json()

    duplicate = client.post("/api/users", json={
        "username": "SUPPORT-AGENT", "password": "another-password-123", "role": "agent"
    })
    assert duplicate.status_code == 409


def test_agent_cannot_manage_users(client):
    database.create_user("support-agent", hash_password("agent-password-123"), "agent")
    login = client.post("/api/login", json={
        "username": "support-agent", "password": "agent-password-123"
    })
    assert login.status_code == 200
    assert client.get("/api/users").status_code == 403
    assert client.post("/api/users", json={
        "username": "another-agent", "password": "another-password-123", "role": "agent"
    }).status_code == 403


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
