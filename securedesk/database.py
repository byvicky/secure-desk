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
    """Manage a SQLite transaction and always close its connection."""
    db = connect()
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'aberto',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE TABLE IF NOT EXISTS audit_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
            event TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
        CREATE INDEX IF NOT EXISTS idx_tickets_priority ON tickets(priority);
        CREATE INDEX IF NOT EXISTS idx_tickets_category ON tickets(category);
        CREATE INDEX IF NOT EXISTS idx_audit_ticket_id ON audit_events(ticket_id, id);
        """)


def create_ticket(data: dict[str, Any]) -> dict[str, Any]:
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO tickets(requester,title,description,category,priority) VALUES(?,?,?,?,?)",
            (data["requester"], data["title"], data["description"], data["category"], data["priority"]),
        )
        ident = cur.lastrowid
        db.execute(
            "INSERT INTO audit_events(ticket_id,event) VALUES(?,?)",
            (ident, "Solicitação registrada"),
        )
        return dict(db.execute("SELECT * FROM tickets WHERE id=?", (ident,)).fetchone())


def list_tickets(limit: int = 50, status: str | None = None,
                 category: str | None = None, priority: str | None = None):
    clauses = []
    values: list[Any] = []
    for column, value in (("status", status), ("category", category), ("priority", priority)):
        if value is not None:
            clauses.append(f"{column}=?")
            values.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    values.append(limit)
    with get_db() as db:
        return [
            dict(row)
            for row in db.execute(
                f"SELECT * FROM tickets {where} ORDER BY created_at DESC,id DESC LIMIT ?", values
            ).fetchall()
        ]


def get_ticket(ticket_id: int):
    with get_db() as db:
        row = db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
        return dict(row) if row else None


def update_status(ticket_id: int, new_status: str):
    with get_db() as db:
        cur = db.execute("UPDATE tickets SET status=? WHERE id=?", (new_status, ticket_id))
        if not cur.rowcount:
            return None
        db.execute(
            "INSERT INTO audit_events(ticket_id,event) VALUES(?,?)",
            (ticket_id, f"Status alterado para {new_status}"),
        )
        return dict(db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone())


def get_ticket_history(ticket_id: int):
    with get_db() as db:
        return [
            dict(row)
            for row in db.execute(
                "SELECT id, ticket_id, event, created_at FROM audit_events "
                "WHERE ticket_id=? ORDER BY id DESC",
                (ticket_id,),
            ).fetchall()
        ]
