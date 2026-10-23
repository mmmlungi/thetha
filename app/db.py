"""SQLite data layer.

Data-management principles (aligned with POPIA):
* Minimisation  - chat messages are never stored; only an anonymous event
                  (intent, risk level, language, province, day) for statistics.
* Encryption    - every column listed in SENSITIVE_COLUMNS holds AES-GCM
                  ciphertext only.
* Erasure       - users can delete everything; secure_delete overwrites freed
                  pages so deleted text doesn't linger in the file.
* Retention     - closed callbacks and old events are purged automatically.
"""
import sqlite3
from datetime import datetime, timedelta, timezone

import click
from flask.cli import with_appcontext
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username_index  TEXT    NOT NULL UNIQUE,   -- HMAC blind index, never the username
    alias_enc       TEXT    NOT NULL,          -- encrypted display name
    password_hash   TEXT    NOT NULL,          -- scrypt hash
    role            TEXT    NOT NULL CHECK (role IN ('survivor', 'counsellor')),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS journal_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    payload_enc TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS safety_plans (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    payload_enc TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS callback_requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ref         TEXT    NOT NULL UNIQUE,
    payload_enc TEXT    NOT NULL,              -- name, phone, safe time, notes
    province    TEXT    NOT NULL,
    urgency     TEXT    NOT NULL CHECK (urgency IN ('normal', 'urgent')),
    status      TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at  TEXT    NOT NULL,
    closed_at   TEXT
);

CREATE TABLE IF NOT EXISTS chat_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    day         TEXT NOT NULL,
    intent      TEXT NOT NULL,
    risk_level  TEXT,
    language    TEXT NOT NULL,
    province    TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor_role  TEXT,
    action      TEXT NOT NULL,
    target      TEXT
);
"""

# (table, column, primary-key column) - checked by tools/security_scan.py
SENSITIVE_COLUMNS = [
    ("users", "alias_enc", "id"),
    ("journal_entries", "payload_enc", "id"),
    ("safety_plans", "payload_enc", "user_id"),
    ("callback_requests", "payload_enc", "id"),
]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, detect_types=0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA secure_delete = ON")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    get_db().executescript(SCHEMA)


def audit(action: str, actor_role: str | None = None, target: str | None = None):
    """Audit trail of who touched sensitive data. Never contains the data itself."""
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (at, actor_role, action, target) VALUES (?, ?, ?, ?)",
        (utcnow(), actor_role, action, target),
    )
    db.commit()


def purge_expired(retention_days: int, event_days: int) -> dict:
    db = get_db()
    now = datetime.now(timezone.utc)
    cb_cutoff = (now - timedelta(days=retention_days)).isoformat(timespec="seconds")
    ev_cutoff = (now - timedelta(days=event_days)).date().isoformat()
    cb = db.execute(
        "DELETE FROM callback_requests WHERE status = 'closed' AND closed_at < ?", (cb_cutoff,)
    ).rowcount
    ev = db.execute("DELETE FROM chat_events WHERE day < ?", (ev_cutoff,)).rowcount
    db.commit()
    return {"callbacks": cb, "events": ev}


@click.command("init-db")
@with_appcontext
def init_db_command():
    init_db()
    click.echo("Database initialised.")


@click.command("purge-expired")
@with_appcontext
def purge_command():
    result = purge_expired(
        current_app.config["CALLBACK_RETENTION_DAYS"], current_app.config["EVENT_RETENTION_DAYS"]
    )
    click.echo(f"Purged {result['callbacks']} closed callbacks and {result['events']} old events.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(purge_command)
    with app.app_context():
        init_db()
