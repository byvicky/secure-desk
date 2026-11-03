from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from securedesk import database, main, security
from securedesk.main import app
from securedesk.security import RateLimiter, hash_password, redact_sensitive_data, verify_password


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "settings", SimpleNamespace(database=str(tmp_path / "auth.db")))
    monkeypatch.setattr(security, "settings", SimpleNamespace(production=True, api_key="test-secret", web_password=""))
    # Keep the global request limiter isolated from unrelated test traffic.
    monkeypatch.setattr(main, "limiter", RateLimiter(limit=1000, window_seconds=60))
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


def test_concurrent_deactivation_cannot_remove_all_active_admins(client):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    first = database.create_user("first-admin", hash_password("first-admin-password-123"), "admin")
    second = database.create_user("second-admin", hash_password("second-admin-password-123"), "admin")
    actor = database.create_user("operator-agent", hash_password("operator-password-123"), "agent")
    barrier = Barrier(2)

    def deactivate(user_id):
        barrier.wait()
        return database.set_user_active(user_id, False, actor["id"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(deactivate, [first["id"], second["id"]]))

    assert sum(error is None for _, error in results) == 1
    assert sum(error == "last_admin" for _, error in results) == 1
    with database.get_db() as db:
        active_admins = db.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin' AND active=1"
        ).fetchone()[0]
    assert active_admins == 1



def test_logout_requires_authentication(client):
    response = client.post("/api/logout")
    assert response.status_code == 401


def test_all_cookie_write_routes_require_csrf(client):
    database.create_user("csrf-admin", hash_password("csrf-admin-password-123"), "admin")
    login = client.post("/api/login", json={
        "username": "csrf-admin", "password": "csrf-admin-password-123"
    })
    assert login.status_code == 200

    write_requests = [
        ("post", "/api/logout", None),
        ("post", "/api/users", {
            "username": "csrf-agent", "password": "csrf-agent-password-123", "role": "agent"
        }),
        ("patch", "/api/users/999/active", {"active": False}),
        ("post", "/api/tickets", {
            "requester": "Solicitante", "title": "Falha no acesso", 
            "description": "Não consigo acessar o sistema interno.", "category": "acesso"
        }),
        ("patch", "/api/tickets/999", {"status": "em_andamento"}),
        ("post", "/api/tickets/999/assignment", {"user_id": None}),
        ("post", "/api/tickets/999/comments", {"body": "Comentário de teste"}),
    ]
    for method, path, payload in write_requests:
        response = getattr(client, method)(path, json=payload) if payload is not None else client.post(path)
        assert response.status_code == 403, f"{method.upper()} {path} não exigiu CSRF"


def test_rate_limiter_is_shared_between_instances(tmp_path, monkeypatch):
    clock = [1_000.0]
    monkeypatch.setattr("securedesk.security.time.time", lambda: clock[0])
    storage = str(tmp_path / "shared-rate-limit.db")
    first_worker = RateLimiter(limit=2, window_seconds=60, storage_path=storage)
    second_worker = RateLimiter(limit=2, window_seconds=60, storage_path=storage)

    assert first_worker.check("shared-client")
    assert second_worker.check("shared-client")
    assert not first_worker.check("shared-client")
    clock[0] += 61
    assert second_worker.check("shared-client")


def test_agent_can_only_work_on_assigned_tickets(client):
    own_agent = database.create_user("own-agent", hash_password("own-agent-password-123"), "agent")
    other_agent = database.create_user("other-agent", hash_password("other-agent-password-123"), "agent")
    database.create_user("ticket-admin", hash_password("ticket-admin-password-123"), "admin")
    admin_login = client.post("/api/login", json={
        "username": "ticket-admin", "password": "ticket-admin-password-123"
    })
    assert admin_login.status_code == 200
    csrf_admin = {"X-CSRF-Token": admin_login.json()["csrf_token"]}
    created = client.post("/api/tickets", headers=csrf_admin, json={
        "requester": "Solicitante", "title": "Acesso ao ambiente", 
        "description": "Não consigo acessar o ambiente de homologação.", "category": "acesso"
    })
    assert created.status_code == 201
    ticket_id = created.json()["id"]
    assigned = client.post(
        f"/api/tickets/{ticket_id}/assignment", headers=csrf_admin,
        json={"user_id": own_agent["id"]}
    )
    assert assigned.status_code == 200

    own_login = client.post("/api/login", json={
        "username": "own-agent", "password": "own-agent-password-123"
    })
    assert own_login.status_code == 200
    own_headers = {"X-CSRF-Token": own_login.json()["csrf_token"]}
    assert client.patch(
        f"/api/tickets/{ticket_id}", headers=own_headers, json={"status": "em_andamento"}
    ).status_code == 200
    assert client.post(
        f"/api/tickets/{ticket_id}/comments", headers=own_headers,
        json={"body": "Estou verificando o acesso."}
    ).status_code == 201

    other_login = client.post("/api/login", json={
        "username": "other-agent", "password": "other-agent-password-123"
    })
    assert other_login.status_code == 200
    other_headers = {"X-CSRF-Token": other_login.json()["csrf_token"]}
    assert client.patch(
        f"/api/tickets/{ticket_id}", headers=other_headers, json={"status": "resolvido"}
    ).status_code == 403
    assert client.post(
        f"/api/tickets/{ticket_id}/comments", headers=other_headers,
        json={"body": "Comentário não autorizado."}
    ).status_code == 403
    assert client.post(
        f"/api/tickets/{ticket_id}/assignment", headers=other_headers,
        json={"user_id": other_agent["id"]}
    ).status_code == 403



def test_agents_only_read_tickets_assigned_to_them(client):
    assigned_agent = database.create_user(
        "assigned-reader", hash_password("assigned-reader-password-123"), "agent"
    )
    database.create_user(
        "other-reader", hash_password("other-reader-password-123"), "agent"
    )
    database.create_user("reader-admin", hash_password("reader-admin-password-123"), "admin")
    admin_login = client.post("/api/login", json={
        "username": "reader-admin", "password": "reader-admin-password-123"
    })
    admin_headers = {"X-CSRF-Token": admin_login.json()["csrf_token"]}

    first = client.post("/api/tickets", headers=admin_headers, json={
        "requester": "Pessoa solicitante", "title": "Chamado atribuído",
        "description": "Descrição do chamado atribuído ao agente.", "category": "acesso"
    })
    second = client.post("/api/tickets", headers=admin_headers, json={
        "requester": "Outra pessoa", "title": "Chamado privado",
        "description": "Descrição de outro chamado sem atribuição.", "category": "hardware"
    })
    assert first.status_code == 201
    assert second.status_code == 201
    ticket_id = first.json()["id"]
    hidden_ticket_id = second.json()["id"]
    assigned = client.post(
        f"/api/tickets/{ticket_id}/assignment", headers=admin_headers,
        json={"user_id": assigned_agent["id"]}
    )
    assert assigned.status_code == 200

    agent_login = client.post("/api/login", json={
        "username": "assigned-reader", "password": "assigned-reader-password-123"
    })
    assert agent_login.status_code == 200
    visible = client.get("/api/tickets")
    assert visible.status_code == 200
    assert [ticket["id"] for ticket in visible.json()] == [ticket_id]

    assert client.get(f"/api/tickets/{ticket_id}").status_code == 200
    assert client.get(f"/api/tickets/{ticket_id}/history").status_code == 200
    assert client.get(f"/api/tickets/{ticket_id}/comments").status_code == 200

    assert client.get(f"/api/tickets/{hidden_ticket_id}").status_code == 404
    assert client.get(f"/api/tickets/{hidden_ticket_id}/history").status_code == 404
    assert client.get(f"/api/tickets/{hidden_ticket_id}/comments").status_code == 404

    other_login = client.post("/api/login", json={
        "username": "other-reader", "password": "other-reader-password-123"
    })
    assert other_login.status_code == 200
    assert client.get("/api/tickets").json() == []
    assert client.get(f"/api/tickets/{ticket_id}").status_code == 404



def test_agent_dashboard_and_assignable_users_are_scoped(client):
    agent = database.create_user("stats-agent", hash_password("stats-agent-password-123"), "agent")
    database.create_user("stats-admin", hash_password("stats-admin-password-123"), "admin")
    login = client.post("/api/login", json={
        "username": "stats-admin", "password": "stats-admin-password-123"
    })
    headers = {"X-CSRF-Token": login.json()["csrf_token"]}
    own = client.post("/api/tickets", headers=headers, json={
        "requester": "Solicitante", "title": "Chamado do agente",
        "description": "Descrição do chamado que será atribuído.", "category": "acesso"
    })
    other = client.post("/api/tickets", headers=headers, json={
        "requester": "Outra pessoa", "title": "Chamado de outro agente",
        "description": "Descrição de outro chamado.", "category": "hardware"
    })
    assert own.status_code == other.status_code == 201
    assert client.post(f"/api/tickets/{own.json()['id']}/assignment",
                       headers=headers, json={"user_id": agent["id"]}).status_code == 200

    agent_login = client.post("/api/login", json={
        "username": "stats-agent", "password": "stats-agent-password-123"
    })
    assert agent_login.status_code == 200
    stats = client.get("/api/dashboard/stats").json()
    assert stats == {"total": 1, "open": 1, "urgent": 0, "resolved": 0}
    assert client.get("/api/users/assignable").status_code == 403


def test_strict_active_flag_and_positive_identifiers(client):
    database.create_user("validation-admin", hash_password("validation-admin-password-123"), "admin")
    login = client.post("/api/login", json={
        "username": "validation-admin", "password": "validation-admin-password-123"
    })
    headers = {"X-CSRF-Token": login.json()["csrf_token"]}
    assert client.patch("/api/users/1/active", headers=headers, json={"active": "false"}).status_code == 422
    assert client.get("/api/tickets/0").status_code == 422
    assert client.post("/api/tickets/1/assignment", headers=headers, json={"user_id": 0}).status_code == 422

def _rate_limit_process_worker(storage_path, start_event, result_queue):
    from securedesk.security import RateLimiter

    limiter = RateLimiter(limit=3, window_seconds=60, storage_path=storage_path)
    start_event.wait(timeout=10)
    result_queue.put(limiter.check("same-client"))


def test_rate_limiter_is_atomic_across_independent_processes(tmp_path):
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    storage = str(tmp_path / "multiprocess-rate-limit.db")
    start_event = context.Event()
    result_queue = context.Queue()
    workers = [
        context.Process(
            target=_rate_limit_process_worker,
            args=(storage, start_event, result_queue),
        )
        for _ in range(8)
    ]

    for worker in workers:
        worker.start()

    start_event.set()
    results = [result_queue.get(timeout=20) for _ in workers]

    for worker in workers:
        worker.join(timeout=20)
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5)
        assert worker.exitcode == 0

    assert sum(results) == 3


def test_rate_limiter_prunes_expired_events_for_other_buckets(tmp_path):
    import sqlite3
    import time

    storage = str(tmp_path / "cleanup-rate-limit.db")
    limiter = RateLimiter(limit=2, window_seconds=60, storage_path=storage)

    with sqlite3.connect(storage) as db:
        db.execute(
            "INSERT INTO rate_limit_events(bucket, occurred_at) VALUES(?, ?)",
            ("inactive-client", time.time() - 120),
        )

    assert limiter.check("active-client")

    with sqlite3.connect(storage) as db:
        remaining = db.execute(
            "SELECT COUNT(*) FROM rate_limit_events WHERE bucket=?",
            ("inactive-client",),
        ).fetchone()[0]

    assert remaining == 0




def test_session_is_invalidated_after_role_change(client):
    user = database.create_user("role-change-user", hash_password("role-change-password-123"), "agent")
    login = client.post("/api/login", json={
        "username": "role-change-user", "password": "role-change-password-123"
    })
    assert login.status_code == 200
    with database.get_db() as db:
        db.execute("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
    assert client.get("/api/tickets").status_code == 401


def test_rate_limiter_failure_fails_closed(client, monkeypatch):
    import sqlite3
    from securedesk import main

    def unavailable(_key):
        raise sqlite3.OperationalError("database unavailable")

    monkeypatch.setattr(main.limiter, "check", unavailable)
    response = client.get("/api/health")
    assert response.status_code == 503
    assert "temporariamente indisponível" in response.json()["detail"]
