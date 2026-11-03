#!/usr/bin/env python3
"""Audit and optionally redact common PII in an existing SecureDesk SQLite database.

Default mode is read-only and reports counts only. --apply creates a SQLite backup
before updating records. Detection is heuristic; it cannot identify every PII type.
"""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

from securedesk.security import redact_sensitive_data

FIELDS = {
    "tickets": ("requester", "title", "description"),
    "ticket_comments": ("body",),
}


def audit(connection: sqlite3.Connection) -> list[tuple[str, str, int]]:
    findings = []
    for table, columns in FIELDS.items():
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if not exists:
            continue
        available = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        for column in columns:
            if column not in available:
                continue
            rows = connection.execute(
                f'SELECT "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL'
            )
            count = sum(
                redact_sensitive_data(row[0]) != row[0]
                for row in rows
            )
            findings.append((table, column, count))
    return findings


def apply_redaction(connection: sqlite3.Connection) -> int:
    changed = 0
    connection.execute("BEGIN IMMEDIATE")
    try:
        for table, columns in FIELDS.items():
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if not exists:
                continue
            available = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            primary_key = "id"
            for column in columns:
                if column not in available:
                    continue
                rows = connection.execute(
                    f'SELECT "{primary_key}", "{column}" FROM "{table}" '
                    f'WHERE "{column}" IS NOT NULL'
                ).fetchall()
                for row_id, value in rows:
                    redacted = redact_sensitive_data(value)
                    if redacted != value:
                        connection.execute(
                            f'UPDATE "{table}" SET "{column}"=? WHERE "{primary_key}"=?',
                            (redacted, row_id),
                        )
                        changed += 1
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--apply", action="store_true", help="Back up and apply heuristic redaction")
    args = parser.parse_args()

    if not args.database.is_file():
        parser.error("database file does not exist")
    with sqlite3.connect(args.database) as db:
        db.row_factory = sqlite3.Row
        findings = audit(db)
        total = sum(count for _, _, count in findings)
        print("Potential records containing recognizable PII (counts only):")
        for table, column, count in findings:
            print(f"- {table}.{column}: {count}")
        print(f"Total field values requiring review: {total}")
        if not args.apply:
            print("Read-only mode. Re-run with --apply to create a backup and redact matches.")
            return 0

        backup = args.database.with_suffix(args.database.suffix + ".pre-pii-redaction.bak")
        if backup.exists():
            parser.error(f"backup already exists; move it before applying: {backup}")
        with sqlite3.connect(backup) as backup_db:
            db.backup(backup_db)
        changed = apply_redaction(db)
        print(f"Updated {changed} field values. Backup: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
