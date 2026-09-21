"""Persistence layer for the Cybersecurity Analyst Workbench.

Kept separate from database.py (the NIDS telemetry store) so the existing,
verified NIDS schema and queries are never disturbed. Both live in the same
SQLite file; workbench tables are prefixed logically by name.
"""
import sqlite3
import json
import logging
from datetime import datetime, timezone

from .config import DB_PATH

logger = logging.getLogger("NIDS.PlatformDB")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_platform_db():
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, username TEXT, event TEXT, detail TEXT, ip TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            analyst TEXT DEFAULT '',
            created_at TEXT, updated_at TEXT,
            status TEXT DEFAULT 'OPEN',
            priority TEXT DEFAULT 'MEDIUM',
            demo INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS case_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_db_id INTEGER NOT NULL,
            item_type TEXT NOT NULL,
            item_ref TEXT DEFAULT '',
            label TEXT DEFAULT '',
            provenance TEXT DEFAULT '',
            added_at TEXT, added_by TEXT DEFAULT ''
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_db_id INTEGER NOT NULL,
            author TEXT DEFAULT '', body TEXT DEFAULT '', created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_db_id INTEGER NOT NULL,
            ts TEXT, kind TEXT, summary TEXT, provenance TEXT, source TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT, ioc_value TEXT,
            result_json TEXT DEFAULT '{}',
            created_at TEXT, analyst TEXT DEFAULT '', demo INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stored_name TEXT, original_name TEXT, size INTEGER,
            md5 TEXT, sha1 TEXT, sha256 TEXT, sha512 TEXT,
            kind TEXT DEFAULT '', uploaded_at TEXT, analyst TEXT DEFAULT '',
            demo INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS log_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stored_name TEXT, original_name TEXT, size INTEGER, lines INTEGER,
            created_at TEXT, analyst TEXT DEFAULT '', demo INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_db_id INTEGER, fmt TEXT, stored_name TEXT,
            created_at TEXT, analyst TEXT DEFAULT ''
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_case_items_case ON case_items (case_db_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_timeline_case ON timeline_events (case_db_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_invest_value ON investigations (ioc_value)")

    conn.commit()
    conn.close()
    logger.info("Platform (workbench) schema initialized.")


# --- users / audit ---

def get_user(username: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username: str, password_hash: str, role: str = "analyst"):
    conn = get_connection()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        (username, password_hash, role, _now()),
    )
    conn.commit()
    conn.close()


def audit(username: str, event: str, detail: str = "", ip: str = ""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (ts, username, event, detail, ip) VALUES (?,?,?,?,?)",
        (_now(), username, event, detail, ip),
    )
    conn.commit()
    conn.close()


def recent_audit(limit: int = 50):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- cases ---

def create_case(case_id, title, description, analyst, status="OPEN", priority="MEDIUM", demo=0):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO cases (case_id,title,description,analyst,created_at,updated_at,status,priority,demo)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (case_id, title, description, analyst, _now(), _now(), status, priority, demo),
    )
    db_id = cur.lastrowid
    conn.commit()
    conn.close()
    return db_id


def get_case_by_code(case_id: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_case(db_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (db_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_cases(demo: int = 0):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM cases WHERE demo = ? ORDER BY id DESC", (demo,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_case(db_id: int, **fields):
    allowed = {"title", "description", "status", "priority", "analyst"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    sets["updated_at"] = _now()
    sql = "UPDATE cases SET " + ", ".join(f"{k} = ?" for k in sets) + " WHERE id = ?"
    conn = get_connection()
    conn.execute(sql, list(sets.values()) + [db_id])
    conn.commit()
    conn.close()


def add_case_item(case_db_id, item_type, item_ref="", label="", provenance="", added_by=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO case_items (case_db_id,item_type,item_ref,label,provenance,added_at,added_by)"
        " VALUES (?,?,?,?,?,?,?)",
        (case_db_id, item_type, item_ref, label, provenance, _now(), added_by),
    )
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (_now(), case_db_id))
    conn.commit()
    conn.close()


def case_items(case_db_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM case_items WHERE case_db_id = ? ORDER BY id", (case_db_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_case_note(case_db_id, author, body):
    conn = get_connection()
    conn.execute(
        "INSERT INTO case_notes (case_db_id,author,body,created_at) VALUES (?,?,?,?)",
        (case_db_id, author, body, _now()),
    )
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (_now(), case_db_id))
    conn.commit()
    conn.close()


def case_notes(case_db_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM case_notes WHERE case_db_id = ? ORDER BY id", (case_db_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_timeline(case_db_id, kind, summary, provenance="", source=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO timeline_events (case_db_id,ts,kind,summary,provenance,source) VALUES (?,?,?,?,?,?)",
        (case_db_id, _now(), kind, summary, provenance, source),
    )
    conn.commit()
    conn.close()


def case_timeline(case_db_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM timeline_events WHERE case_db_id = ? ORDER BY ts, id", (case_db_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- investigations / files / logs / reports ---

def save_investigation(ioc_type, ioc_value, result: dict, analyst="", demo=0):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO investigations (ioc_type,ioc_value,result_json,created_at,analyst,demo)"
        " VALUES (?,?,?,?,?,?)",
        (ioc_type, ioc_value, json.dumps(result), _now(), analyst, demo),
    )
    iid = cur.lastrowid
    conn.commit()
    conn.close()
    return iid


def get_investigation(iid: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (iid,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["result"] = json.loads(d.pop("result_json") or "{}")
    return d


def recent_investigations(limit=50, demo=0):
    conn = get_connection()
    rows = conn.execute(
        "SELECT id,ioc_type,ioc_value,created_at,analyst,demo FROM investigations"
        " WHERE demo = ? ORDER BY id DESC LIMIT ?", (demo, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_uploaded_file(stored_name, original_name, size, hashes: dict, kind="", analyst="", demo=0):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO uploaded_files (stored_name,original_name,size,md5,sha1,sha256,sha512,kind,uploaded_at,analyst,demo)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (stored_name, original_name, size, hashes.get("md5"), hashes.get("sha1"),
         hashes.get("sha256"), hashes.get("sha512"), kind, _now(), analyst, demo),
    )
    fid = cur.lastrowid
    conn.commit()
    conn.close()
    return fid


def get_uploaded_file(fid: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM uploaded_files WHERE id = ?", (fid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def recent_files(limit=50, demo=0):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM uploaded_files WHERE demo = ? ORDER BY id DESC LIMIT ?", (demo, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_log_job(stored_name, original_name, size, lines, analyst="", demo=0):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO log_jobs (stored_name,original_name,size,lines,created_at,analyst,demo)"
        " VALUES (?,?,?,?,?,?,?)",
        (stored_name, original_name, size, lines, _now(), analyst, demo),
    )
    lid = cur.lastrowid
    conn.commit()
    conn.close()
    return lid


def get_log_job(lid: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM log_jobs WHERE id = ?", (lid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def recent_log_jobs(limit=50, demo=0):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM log_jobs WHERE demo = ? ORDER BY id DESC LIMIT ?", (demo, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_report(case_db_id, fmt, stored_name, analyst=""):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO reports (case_db_id,fmt,stored_name,created_at,analyst) VALUES (?,?,?,?,?)",
        (case_db_id, fmt, stored_name, _now(), analyst),
    )
    rid = cur.lastrowid
    conn.commit()
    conn.close()
    return rid


def recent_reports(limit=50):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
