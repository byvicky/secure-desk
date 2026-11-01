import pytest
from types import SimpleNamespace
from fastapi.testclient import TestClient

from securedesk import database
from securedesk.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "settings", SimpleNamespace(database=str(tmp_path / "test.db")) )
    with TestClient(app) as test_client:
        yield test_client


def test_health_and_frontend_assets(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_ticket_lifecycle_and_redaction(client):
    payload = {
        "requester": "Maria",
        "title": "Recebi um phishing",
        "description": "O e-mail suspeito foi enviado para maria@example.com",
    }
    created = client.post("/api/tickets", json=payload)
    assert created.status_code == 201
    ticket = created.json()
    assert ticket["category"] == "seguranca"
    assert ticket["priority"] == "critica"
    assert "maria@example.com" not in ticket["description"]
    assert client.get(f"/api/tickets/{ticket['id']}").status_code == 200
    updated = client.patch(f"/api/tickets/{ticket['id']}", json={"status": "resolvido"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "resolvido"
    assert client.get("/api/tickets").json()[0]["id"] == ticket["id"]


def test_validation_and_not_found(client):
    assert client.post("/api/tickets", json={"requester": "x"}).status_code == 422
    assert client.post(
        "/api/tickets",
        json={
            "requester": "Ana",
            "title": "Título válido",
            "description": "Descrição válida para teste",
            "unexpected": "nope",
        },
    ).status_code == 422
    assert client.get("/api/tickets/9999").status_code == 404
    assert client.patch("/api/tickets/9999", json={"status": "resolvido"}).status_code == 404


def test_security_headers_present(client):
    response = client.get("/api/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "Content-Security-Policy" in response.headers
