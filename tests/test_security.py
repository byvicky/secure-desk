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

    csrf = response.json()["csrf_token"]
    created = client.post("/api/users", headers={"X-CSRF-Token": csrf}, json={
        "username": "support-agent", "password": "agent-password-123", "role": "agent"
    })
    assert created.status_code == 201
    assert created.json()["username"] == "support-agent"
    assert "password_hash" not in created.json()

    duplicate = client.post("/api/users", headers={"X-CSRF-Token": csrf}, json={
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
    assert client.post("/api/users", headers={"X-CSRF-Token": login.json()["csrf_token"]}, json={
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



def test_csrf_token_required_for_cookie_authenticated_changes(client):
    database.create_user("admin-user", hash_password("admin-password-123"), "admin")
    login = client.post("/api/login", json={
        "username": "admin-user", "password": "admin-password-123"
    })
    assert login.status_code == 200
    assert client.post("/api/users", json={
        "username": "without-token", "password": "agent-password-123", "role": "agent"
    }).status_code == 403
    token = login.json()["csrf_token"]
    created = client.post("/api/users", headers={"X-CSRF-Token": token}, json={
        "username": "with-token", "password": "agent-password-123", "role": "agent"
    })
    assert created.status_code == 201


def test_login_attempts_are_limited(client, monkeypatch):
    from securedesk import main

    monkeypatch.setattr(main, "login_limiter", RateLimiter(limit=2, window_seconds=900))
    for _ in range(2):
        assert client.post("/api/login", json={
            "username": "missing", "password": "wrong-password"
        }).status_code == 401
    assert client.post("/api/login", json={
        "username": "missing", "password": "wrong-password"
    }).status_code == 429


def test_deactivated_user_session_is_rejected(client):
    user = database.create_user("revoked-user", hash_password("revoked-password-123"), "agent")
    login = client.post("/api/login", json={
        "username": "revoked-user", "password": "revoked-password-123"
    })
    assert login.status_code == 200
    database.set_user_active(user["id"], False, 999)
    response = client.get("/api/tickets")
    assert response.status_code == 401


def test_password_verification_rejects_unsafe_hash_parameters(monkeypatch):
    # Invalid iteration counts must be rejected before PBKDF2 is invoked.
    def forbidden_pbkdf2(*args, **kwargs):
        raise AssertionError("PBKDF2 must not run for an unsafe stored hash")

    monkeypatch.setattr(security.hashlib, "pbkdf2_hmac", forbidden_pbkdf2)
    assert not verify_password("password", "pbkdf2_sha256$999999999$" + ("00" * 16) + "$" + ("00" * 32))
    assert not verify_password("password", "pbkdf2_sha256$1$" + ("00" * 16) + "$" + ("00" * 32))
    assert not verify_password("password", "pbkdf2_sha256$310000$00$" + ("00" * 32))


def test_production_requires_strong_session_secret(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    from securedesk import main

    monkeypatch.setattr(main, "settings", SimpleNamespace(
        production=True, session_secret="weak", admin_password="", admin_username="admin"
    ))
    monkeypatch.setattr(database, "settings", SimpleNamespace(database=str(tmp_path / "prod.db")))
    with pytest.raises(RuntimeError, match="SECUREDESK_SESSION_SECRET"), TestClient(app):
        pass
