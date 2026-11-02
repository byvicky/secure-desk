import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from securedesk.config import settings


def connect():
    path = Path(settings.database)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db


@contextmanager
def get_db():
    db = connect()
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','agent')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'aberto',
            assigned_to INTEGER REFERENCES users(id),
            created_by INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS audit_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
            event TEXT NOT NULL,
            actor_user_id INTEGER REFERENCES users(id),
            actor_username TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS ticket_comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id),
            username TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
        CREATE INDEX IF NOT EXISTS idx_tickets_priority ON tickets(priority);
        CREATE INDEX IF NOT EXISTS idx_tickets_category ON tickets(category);
        CREATE INDEX IF NOT EXISTS idx_audit_ticket_id ON audit_events(ticket_id, id);
        CREATE INDEX IF NOT EXISTS idx_comments_ticket ON ticket_comments(ticket_id,id);
        """)
        ticket_columns = {row["name"] for row in db.execute("PRAGMA table_info(tickets)")}
        for column in ("assigned_to", "created_by"):
            if column not in ticket_columns:
                db.execute(f"ALTER TABLE tickets ADD COLUMN {column} INTEGER REFERENCES users(id)")
        audit_columns = {row["name"] for row in db.execute("PRAGMA table_info(audit_events)")}
        if "actor_user_id" not in audit_columns:
            db.execute("ALTER TABLE audit_events ADD COLUMN actor_user_id INTEGER REFERENCES users(id)")
        if "actor_username" not in audit_columns:
            db.execute("ALTER TABLE audit_events ADD COLUMN actor_username TEXT")


def create_user(username: str, password_hash: str, role: str = "agent") -> dict[str, Any]:
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
            (username, password_hash, role),
        )
        return dict(db.execute(
            "SELECT id,username,role,active,created_at FROM users WHERE id=?", (cur.lastrowid,)
        ).fetchone())


def ensure_bootstrap_admin(username: str, password_hash: str):
    if not username or not password_hash:
        return
    with get_db() as db:
        exists = db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?, 'admin')",
                (username, password_hash),
            )


def get_user_by_username(username: str):
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        return dict(row) if row else None


def list_users():
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT id,username,role,active,created_at FROM users ORDER BY id"
        ).fetchall()]


def list_assignable_users():
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT id,username,role FROM users WHERE active=1 ORDER BY username"
        ).fetchall()]


def create_ticket(data: dict[str, Any], actor: dict | None = None) -> dict[str, Any]:
    actor_id = actor.get("id") if actor and actor.get("id", 0) > 0 else None
    actor_name = actor.get("username") if actor else "system"
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO tickets(requester,title,description,category,priority,created_by) VALUES(?,?,?,?,?,?)",
            (data["requester"], data["title"], data["description"], data["category"], data["priority"], actor_id),
        )
        ident = cur.lastrowid
        db.execute(
            "INSERT INTO audit_events(ticket_id,event,actor_user_id,actor_username) VALUES(?,?,?,?)",
            (ident, "Solicitação registrada", actor_id, actor_name),
        )
        return dict(db.execute("SELECT * FROM tickets WHERE id=?", (ident,)).fetchone())


def list_tickets(limit: int = 50, status: str | None = None,
                 category: str | None = None, priority: str | None = None,
                 search: str | None = None):
    clauses = []
    values: list[Any] = []
    for column, value in (("status", status), ("category", category), ("priority", priority)):
        if value is not None:
            clauses.append(f"{column}=?")
            values.append(value)
    if search and search.strip():
        clauses.append("(title LIKE ? OR description LIKE ? OR requester LIKE ?)")
        term = f"%{search.strip()}%"
        values.extend([term, term, term])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    values.append(limit)
    with get_db() as db:
        return [dict(row) for row in db.execute(
            f"SELECT * FROM tickets {where} ORDER BY created_at DESC,id DESC LIMIT ?", values
        ).fetchall()]


def get_ticket(ticket_id: int):
    with get_db() as db:
        row = db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
        return dict(row) if row else None


def update_status(ticket_id: int, new_status: str, actor: dict | None = None):
    actor_id = actor.get("id") if actor and actor.get("id", 0) > 0 else None
    actor_name = actor.get("username") if actor else "system"
    with get_db() as db:
        cur = db.execute("UPDATE tickets SET status=? WHERE id=?", (new_status, ticket_id))
        if not cur.rowcount:
            return None
        db.execute(
            "INSERT INTO audit_events(ticket_id,event,actor_user_id,actor_username) VALUES(?,?,?,?)",
            (ticket_id, f"Status alterado para {new_status}", actor_id, actor_name),
        )
        return dict(db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone())


def assign_ticket(ticket_id: int, user_id: int | None, actor: dict):
    actor_id = actor.get("id") if actor.get("id", 0) > 0 else None
    with get_db() as db:
        assignee = None
        if user_id is not None:
            assignee = db.execute(
                "SELECT id,username FROM users WHERE id=? AND active=1", (user_id,)
            ).fetchone()
            if not assignee:
                return None
        cur = db.execute("UPDATE tickets SET assigned_to=? WHERE id=?", (user_id, ticket_id))
        if not cur.rowcount:
            return None
        label = assignee["username"] if assignee else "Não atribuído"
        db.execute(
            "INSERT INTO audit_events(ticket_id,event,actor_user_id,actor_username) VALUES(?,?,?,?)",
            (ticket_id, f"Chamado atribuído a {label}", actor_id, actor["username"]),
        )
        return dict(db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone())


def add_comment(ticket_id: int, body: str, actor: dict):
    actor_id = actor.get("id") if actor.get("id", 0) > 0 else None
    with get_db() as db:
        if not db.execute("SELECT id FROM tickets WHERE id=?", (ticket_id,)).fetchone():
            return None
        cur = db.execute(
            "INSERT INTO ticket_comments(ticket_id,user_id,username,body) VALUES(?,?,?,?)",
            (ticket_id, actor_id, actor["username"], body),
        )
        db.execute(
            "INSERT INTO audit_events(ticket_id,event,actor_user_id,actor_username) VALUES(?,?,?,?)",
            (ticket_id, "Comentário adicionado", actor_id, actor["username"]),
        )
        return dict(db.execute(
            "SELECT id,ticket_id,user_id,username,body,created_at FROM ticket_comments WHERE id=?",
            (cur.lastrowid,),
        ).fetchone())


def list_comments(ticket_id: int):
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT id,ticket_id,user_id,username,body,created_at FROM ticket_comments WHERE ticket_id=? ORDER BY id",
            (ticket_id,),
        ).fetchall()]


def get_ticket_history(ticket_id: int):
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT id,ticket_id,event,actor_user_id,actor_username,created_at FROM audit_events WHERE ticket_id=? ORDER BY id DESC",
            (ticket_id,),
        ).fetchall()]


def set_user_active(user_id: int, active: bool, actor_id: int):
    with get_db() as db:
        target = db.execute(
            "SELECT id,username,role,active FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if target is None:
            return None, "not_found"
        if user_id == actor_id and not active:
            return None, "self"
        if target["role"] == "admin" and target["active"] and not active:
            active_admins = db.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND active=1"
            ).fetchone()[0]
            if active_admins <= 1:
                return None, "last_admin"
        db.execute("UPDATE users SET active=? WHERE id=?", (int(active), user_id))
        row = db.execute(
            "SELECT id,username,role,active,created_at FROM users WHERE id=?", (user_id,)
        ).fetchone()
        return dict(row), None


def ticket_stats():
    with get_db() as db:
        row = db.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='aberto' THEN 1 ELSE 0 END) AS open,
                   SUM(CASE WHEN priority IN ('alta','critica') THEN 1 ELSE 0 END) AS urgent,
                   SUM(CASE WHEN status='resolvido' THEN 1 ELSE 0 END) AS resolved
            FROM tickets
        """).fetchone()
        return {key: row[key] or 0 for key in ("total", "open", "urgent", "resolved")}


def get_user_by_id(user_id: int):
    with get_db() as db:
        row = db.execute(
            "SELECT id,username,role,active FROM users WHERE id=?", (user_id,)
        ).fetchone()
        return dict(row) if row else None
