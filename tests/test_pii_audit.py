import sqlite3

from scripts import audit_pii


def test_pii_audit_is_read_only_and_apply_creates_backup(tmp_path, monkeypatch):
    database_path = tmp_path / "securedesk.db"
    with sqlite3.connect(database_path) as db:
        db.executescript("""
            CREATE TABLE tickets (
                id INTEGER PRIMARY KEY,
                requester TEXT,
                title TEXT,
                description TEXT
            );
            CREATE TABLE ticket_comments (
                id INTEGER PRIMARY KEY,
                body TEXT
            );
            INSERT INTO tickets VALUES (
                1, 'Ana ana@example.com', 'CPF 12345678900',
                'Solicitação de teste com telefone 11987654321'
            );
            INSERT INTO ticket_comments VALUES (1, 'Contato ana@example.com');
        """)

    with sqlite3.connect(database_path) as db:
        findings = audit_pii.audit(db)
    assert ("tickets", "requester", 1) in findings
    assert ("tickets", "title", 1) in findings
    assert ("ticket_comments", "body", 1) in findings

    monkeypatch.setattr(
        "sys.argv", ["audit_pii", "--database", str(database_path)]
    )
    assert audit_pii.main() == 0
    with sqlite3.connect(database_path) as db:
        assert "ana@example.com" in db.execute(
            "SELECT requester FROM tickets WHERE id=1"
        ).fetchone()[0]

    monkeypatch.setattr(
        "sys.argv", ["audit_pii", "--database", str(database_path), "--apply"]
    )
    assert audit_pii.main() == 0

    backup_path = database_path.with_suffix(".db.pre-pii-redaction.bak")
    assert backup_path.is_file()
    with sqlite3.connect(database_path) as db:
        requester, title, description = db.execute(
            "SELECT requester,title,description FROM tickets WHERE id=1"
        ).fetchone()
        comment = db.execute(
            "SELECT body FROM ticket_comments WHERE id=1"
        ).fetchone()[0]
    assert "ana@example.com" not in requester
    assert "12345678900" not in title
    assert "11987654321" not in description
    assert "ana@example.com" not in comment
    with sqlite3.connect(backup_path) as backup:
        assert "ana@example.com" in backup.execute(
            "SELECT requester FROM tickets WHERE id=1"
        ).fetchone()[0]
