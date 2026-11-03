from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from securedesk import database
from securedesk.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "settings", SimpleNamespace(database=str(tmp_path / "test.db")))
    with TestClient(app) as test_client:
        yield test_client


def ticket(client, title, description, category=None):
    payload = {"requester": "Maria", "title": title, "description": description}
    if category:
        payload["category"] = category
    response = client.post("/api/tickets", json=payload)
    assert response.status_code == 201
    return response.json()


def test_health_and_frontend_assets(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_ticket_lifecycle_and_redaction(client):
    created = ticket(client, "Recebi um phishing", "O e-mail suspeito foi enviado para maria@example.com")
    assert created["category"] == "seguranca"
    assert created["priority"] == "critica"
    assert "maria@example.com" not in created["description"]
    assert client.get(f"/api/tickets/{created['id']}").status_code == 200
    updated = client.patch(f"/api/tickets/{created['id']}", json={"status": "resolvido"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "resolvido"
    assert client.get("/api/tickets").json()[0]["id"] == created["id"]


def test_validation_and_not_found(client):
    assert client.post("/api/tickets", json={"requester": "x"}).status_code == 422
    assert client.post("/api/tickets", json={
        "requester": "Ana", "title": "Título válido",
        "description": "Descrição válida para teste", "unexpected": "nope",
    }).status_code == 422
    assert client.get("/api/tickets/9999").status_code == 404
    assert client.patch("/api/tickets/9999", json={"status": "resolvido"}).status_code == 404


def test_security_headers_present(client):
    response = client.get("/api/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "Content-Security-Policy" in response.headers
    assert response.headers["x-request-id"]


def test_multiline_description_is_accepted(client):
    response = client.post("/api/tickets", json={
        "requester": "Joana", "title": "Falha no computador",
        "description": "O computador não inicia.\nA tela fica preta.",
    })
    assert response.status_code == 201
    assert "\n" in response.json()["description"]


def test_ticket_audit_history(client):
    created = ticket(client, "Acesso bloqueado", "Não consigo acessar minha conta corporativa.")
    ticket_id = created["id"]
    initial = client.get(f"/api/tickets/{ticket_id}/history")
    assert initial.status_code == 200
    assert [event["event"] for event in initial.json()] == ["Solicitação registrada"]
    changed = client.patch(f"/api/tickets/{ticket_id}", json={"status": "em_andamento"})
    assert changed.status_code == 200
    history = client.get(f"/api/tickets/{ticket_id}/history")
    assert [event["event"] for event in history.json()] == [
        "Status alterado para em_andamento", "Solicitação registrada"
    ]


def test_ticket_history_not_found(client):
    assert client.get("/api/tickets/98765/history").status_code == 404


def test_ticket_filters_can_be_combined(client):
    open_security = ticket(client, "Alerta de phishing", "Mensagem suspeita recebida.")
    resolved_access = ticket(client, "Senha bloqueada", "Não consigo entrar no sistema.")
    client.patch(f"/api/tickets/{resolved_access['id']}", json={"status": "resolvido"})

    assert [x["id"] for x in client.get("/api/tickets?category=seguranca").json()] == [
        open_security["id"]
    ]
    assert [x["id"] for x in client.get("/api/tickets?status=resolvido").json()] == [
        resolved_access["id"]
    ]
    filtered = client.get("/api/tickets?status=resolvido&category=acesso&priority=media")
    assert [x["id"] for x in filtered.json()] == [resolved_access["id"]]


def test_ticket_filters_reject_invalid_values(client):
    assert client.get("/api/tickets?status=closed").status_code == 422
    assert client.get("/api/tickets?category=unknown").status_code == 422
    assert client.get("/api/tickets?priority=urgent").status_code == 422
    assert client.get("/api/tickets?limit=101").status_code == 422


def test_assignment_comments_and_actor_audit(client):
    from securedesk.security import hash_password

    agent = database.create_user("assigned-agent", hash_password("a-long-agent-password"), "agent")
    created = ticket(client, "Falha no acesso VPN", "Não consigo conectar à VPN corporativa.")
    ticket_id = created["id"]

    assignable = client.get("/api/users/assignable")
    assert assignable.status_code == 200
    assert any(user["id"] == agent["id"] for user in assignable.json())

    assigned = client.post(
        f"/api/tickets/{ticket_id}/assignment", json={"user_id": agent["id"]}
    )
    assert assigned.status_code == 200
    assert assigned.json()["assigned_to"] == agent["id"]

    comment = client.post(
        f"/api/tickets/{ticket_id}/comments",
        json={"body": "Estou verificando a configuração da VPN."},
    )
    assert comment.status_code == 201
    assert comment.json()["username"] == "local-dev"
    assert client.get(f"/api/tickets/{ticket_id}/comments").json()[0]["body"] == (
        "Estou verificando a configuração da VPN."
    )

    history = client.get(f"/api/tickets/{ticket_id}/history").json()
    assert history[0]["event"] == "Comentário adicionado"
    assert history[0]["actor_username"] == "local-dev"
    assert any(item["event"] == "Chamado atribuído a assigned-agent" for item in history)


def test_assignment_rejects_inactive_or_missing_user(client):
    created = ticket(client, "Falha no monitor", "O monitor não apresenta imagem.")
    response = client.post(
        f"/api/tickets/{created['id']}/assignment", json={"user_id": 9999}
    )
    assert response.status_code == 404


def test_ticket_search_and_dashboard_stats(client):
    match = ticket(client, "Erro no acesso ao portal", "Falha ao entrar no portal interno.")
    ticket(client, "Teclado sem resposta", "O teclado parou de funcionar.")
    response = client.get("/api/tickets?search=portal")
    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [match["id"]]

    stats = client.get("/api/dashboard/stats")
    assert stats.status_code == 200
    assert stats.json()["total"] >= 2
    assert stats.json()["open"] >= 2


def test_admin_can_deactivate_agent_but_not_last_admin_or_self(client):
    from securedesk.security import hash_password

    agent = database.create_user("deactivate-agent", hash_password("a-long-agent-password"), "agent")
    response = client.patch(f"/api/users/{agent['id']}/active", json={"active": False})
    assert response.status_code == 200
    assert response.json()["active"] == 0
    assert all(user["id"] != agent["id"] for user in client.get("/api/users/assignable").json())

    admin = database.create_user("only-admin", hash_password("a-long-admin-password"), "admin")
    protected = client.patch(f"/api/users/{admin['id']}/active", json={"active": False})
    assert protected.status_code == 409


def test_comment_redaction_masks_personal_data(client):
    created = ticket(client, "Solicitação de suporte", "Descrição válida para abrir o chamado.")
    comment = client.post(
        f"/api/tickets/{created['id']}/comments",
        json={"body": "Contato ana@example.com, CPF 123.456.789-00 e telefone 11987654321."},
    )
    assert comment.status_code == 201
    body = comment.json()["body"]
    assert "ana@example.com" not in body
    assert "123.456.789-00" not in body
    assert "11987654321" not in body
    assert "[EMAIL REDIGIDO]" in body
    assert "[CPF REDIGIDO]" in body
    assert "[TELEFONE REDIGIDO]" in body


def test_redaction_masks_unformatted_cpf():
    result = redact_sensitive_data("CPF 12345678900")
    assert "12345678900" not in result
    assert "[CPF REDIGIDO]" in result
