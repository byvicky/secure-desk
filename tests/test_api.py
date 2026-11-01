from types import SimpleNamespace

from fastapi.testclient import TestClient

from securedesk import database
from securedesk.main import app


def test_complete_ticket_flow_and_static_frontend(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "settings",
        SimpleNamespace(database=str(tmp_path / "securedesk-test.db")),
    )

    with TestClient(app) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "SecureDesk" in page.text
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/api/health").json()["status"] == "ok"

        invalid = client.post(
            "/api/tickets",
            json={"requester": "A", "title": "oi", "description": "curta"},
        )
        assert invalid.status_code == 422

        created = client.post(
            "/api/tickets",
            json={
                "requester": "Ana",
                "title": "E-mail suspeito",
                "description": "Recebi phishing no ana@example.com e CPF 123.456.789-00",
            },
        )
        assert created.status_code == 201
        ticket = created.json()
        assert ticket["category"] == "seguranca"
        assert ticket["priority"] == "critica"
        assert "ana@example.com" not in ticket["description"]
        assert "[EMAIL REDIGIDO]" in ticket["description"]
        assert "123.456.789-00" not in ticket["description"]
        assert "[CPF REDIGIDO]" in ticket["description"]

        ticket_id = ticket["id"]
        assert client.get(f"/api/tickets/{ticket_id}").status_code == 200
        assert len(client.get("/api/tickets").json()) == 1

        updated = client.patch(
            f"/api/tickets/{ticket_id}",
            json={"status": "resolvido"},
        )
        assert updated.status_code == 200
        assert updated.json()["status"] == "resolvido"

        assert client.get("/api/tickets/99999").status_code == 404
        assert client.patch(
            f"/api/tickets/{ticket_id}",
            json={"status": "nao_existe"},
        ).status_code == 422

        assert page.headers.get("x-content-type-options") == "nosniff"


def test_unknown_fields_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "settings",
        SimpleNamespace(database=str(tmp_path / "securedesk-validation.db")),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/tickets",
            json={
                "requester": "Ana",
                "title": "Computador não liga",
                "description": "O equipamento não inicia desde hoje.",
                "is_admin": True,
            },
        )
        assert response.status_code == 422
