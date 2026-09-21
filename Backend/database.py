import sqlite3
import json
import logging
from datetime import datetime, timedelta, timezone
import os
from .config import DB_PATH, ACTIVE_THREAT_WINDOW

logger = logging.getLogger("NIDS.Database")

def get_connection():
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema if tables do not exist."""
    logger.info(f"Initializing database at: {DB_PATH}")
    conn = get_connection()
    cursor = conn.cursor()

    # Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0.90,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT DEFAULT 'TCP',
            details TEXT,
            status TEXT DEFAULT 'ACTIVE',
            asset_ip TEXT DEFAULT '',
            evidence TEXT DEFAULT '{}',
            first_seen REAL,
            last_seen REAL
        )
    """)

    # Migration: add asset-monitoring columns to databases created before this schema.
    existing_cols = {row["name"] for row in cursor.execute("PRAGMA table_info(alerts)").fetchall()}
    for col, ddl in (
        ("asset_ip", "ALTER TABLE alerts ADD COLUMN asset_ip TEXT DEFAULT ''"),
        ("evidence", "ALTER TABLE alerts ADD COLUMN evidence TEXT DEFAULT '{}'"),
        ("first_seen", "ALTER TABLE alerts ADD COLUMN first_seen REAL"),
        ("last_seen", "ALTER TABLE alerts ADD COLUMN last_seen REAL"),
    ):
        if col not in existing_cols:
            cursor.execute(ddl)

    # Traffic Stats Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            total_alerts INTEGER DEFAULT 0
        )
    """)

    # Packet Logs Table (Sampled recent network traffic)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            length INTEGER,
            flags TEXT
        )
    """)

    # Insert initial traffic stats row if empty
    cursor.execute("SELECT COUNT(*) FROM traffic_stats")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO traffic_stats (total_packets, total_bytes, total_alerts) VALUES (0, 0, 0)")

    # Indexes for windowed/status queries used by the metrics endpoints.
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status)")

    conn.commit()
    conn.close()
    logger.info("Database schema initialized successfully.")

def save_alert(alert_data):
    """Inserts a new alert into the database and updates statistics."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO alerts 
            (timestamp, attack_type, severity, confidence, source_ip, destination_ip, source_port, destination_port, protocol, details, status, asset_ip, evidence, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            alert_data.get("attack_type", "UNKNOWN"),
            alert_data.get("severity", "MEDIUM"),
            alert_data.get("confidence", 0.85),
            alert_data.get("source_ip", "0.0.0.0"),
            alert_data.get("destination_ip", "0.0.0.0"),
            alert_data.get("source_port", 0),
            alert_data.get("destination_port", 0),
            alert_data.get("protocol", "TCP"),
            alert_data.get("details", ""),
            alert_data.get("status", "ACTIVE"),
            alert_data.get("asset_ip", ""),
            json.dumps(alert_data.get("evidence", {}) or {}),
            alert_data.get("first_seen"),
            alert_data.get("last_seen"),
        ))
        alert_id = cursor.lastrowid
        
        # Update total alerts counter in traffic stats
        cursor.execute("UPDATE traffic_stats SET total_alerts = total_alerts + 1 WHERE id = 1")
        
        conn.commit()
        logger.info(f"Alert #{alert_id} persisted: {alert_data.get('attack_type')} from {alert_data.get('source_ip')}")
        return alert_id
    except Exception as e:
        logger.error(f"Error saving alert to DB: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def save_packet(packet_data):
    """Saves packet metadata and updates total packets counter."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO packet_logs 
            (timestamp, source_ip, destination_ip, source_port, destination_port, protocol, length, flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            packet_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            packet_data.get("source_ip"),
            packet_data.get("destination_ip"),
            packet_data.get("source_port"),
            packet_data.get("destination_port"),
            packet_data.get("protocol", "IP"),
            packet_data.get("length", 0),
            packet_data.get("flags", "")
        ))
        
        length = packet_data.get("length", 0)
        cursor.execute("UPDATE traffic_stats SET total_packets = total_packets + 1, total_bytes = total_bytes + ? WHERE id = 1", (length,))
        
        conn.commit()
    except Exception as e:
        logger.error(f"Error saving packet log: {e}")
        conn.rollback()
    finally:
        conn.close()

def increment_packet_count(count=1, total_bytes=0):
    """Increments overall packet counters without logging every packet details."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE traffic_stats SET total_packets = total_packets + ?, total_bytes = total_bytes + ? WHERE id = 1", (count, total_bytes))
        conn.commit()
    except Exception as e:
        logger.error(f"Error incrementing packet stats: {e}")
    finally:
        conn.close()

def get_all_alerts(limit=100, severity=None, attack_type=None):
    """Retrieves recent alerts with optional filters."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM alerts"
    conditions = []
    params = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if attack_type:
        conditions.append("attack_type = ?")
        params.append(attack_type)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [_hydrate_alert(dict(row)) for row in rows]


def _hydrate_alert(row: dict) -> dict:
    """Parses the stored JSON evidence back into a dict for API consumers."""
    try:
        row["evidence"] = json.loads(row.get("evidence") or "{}")
    except (TypeError, ValueError):
        row["evidence"] = {}
    return row


def get_alert(alert_id: int):
    """Returns a single alert by id, or None."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return _hydrate_alert(dict(row)) if row else None


def resolve_alert(alert_id: int) -> bool:
    """Marks an alert RESOLVED so it no longer counts as an active threat."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE alerts SET status = 'RESOLVED' WHERE id = ?", (alert_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Error resolving alert {alert_id}: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def _active_cutoff_iso(window_seconds: int = ACTIVE_THREAT_WINDOW) -> str:
    """ISO-8601 UTC cutoff. Alerts with timestamp >= this are considered active.

    Matches the format produced by Alert.timestamp (datetime.now(timezone.utc).isoformat()),
    so lexicographic comparison is chronologically correct.
    """
    return (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()


def get_active_threats(limit=100, window_seconds: int = ACTIVE_THREAT_WINDOW):
    """Returns unresolved alerts within the active-threat window (most recent first)."""
    cutoff = _active_cutoff_iso(window_seconds)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM alerts WHERE timestamp >= ? AND status = 'ACTIVE' ORDER BY id DESC LIMIT ?",
        (cutoff, limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_stats():
    """Retrieves cumulative and real-time dashboard analytics statistics.

    Metric definitions:
      - total_packets/total_bytes/total_alerts: cumulative lifetime counters.
      - total_attacks: total alert rows ever recorded (historical).
      - active_threats: alert rows within the ACTIVE_THREAT_WINDOW (currently active),
        distinguished from historical detections.
      - detection_rate: total_alerts / total_packets over the lifetime, expressed as a
        percentage. Denominator is every analyzed packet; numerator is deduplicated
        alert events. Reported alongside its raw components for transparency.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Get overall counts
    cursor.execute("SELECT total_packets, total_bytes, total_alerts FROM traffic_stats WHERE id = 1")
    stat_row = cursor.fetchone()
    total_packets = stat_row["total_packets"] if stat_row else 0
    total_bytes = stat_row["total_bytes"] if stat_row else 0
    total_alerts = stat_row["total_alerts"] if stat_row else 0

    # Active threats: unresolved alerts within the configured recency window
    cutoff = _active_cutoff_iso()
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp >= ? AND status = 'ACTIVE'", (cutoff,))
    active_threats = cursor.fetchone()[0]

    # Resolved alerts (explicitly marked RESOLVED)
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'RESOLVED'")
    resolved_alerts = cursor.fetchone()[0]

    # Historical alerts: older than the active window (regardless of status)
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp < ?", (cutoff,))
    historical_alerts = cursor.fetchone()[0]

    # Total Attacks count (historical detections)
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_attacks = cursor.fetchone()[0]

    # Attack Types Distribution
    cursor.execute("SELECT attack_type, COUNT(*) as count FROM alerts GROUP BY attack_type")
    attack_types = {row["attack_type"]: row["count"] for row in cursor.fetchall()}

    # Severity Distribution
    cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
    severity_dist = {row["severity"]: row["count"] for row in cursor.fetchall()}

    # Top Attacker IPs
    cursor.execute("SELECT source_ip, COUNT(*) as count FROM alerts GROUP BY source_ip ORDER BY count DESC LIMIT 5")
    top_attackers = [{"ip": row["source_ip"], "count": row["count"]} for row in cursor.fetchall()]

    conn.close()

    # Detection rate: alerts per analyzed packet (lifetime). Units are explicit and the
    # raw components are exposed so consumers can reinterpret if needed.
    detection_rate_value = round((total_alerts / total_packets) * 100, 2) if total_packets else 0.0

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_alerts": total_alerts,
        "total_attacks": total_attacks,
        "detections": total_attacks,
        "active_threats": active_threats,
        "active_alerts": active_threats,
        "resolved_alerts": resolved_alerts,
        "historical_alerts": historical_alerts,
        "active_window_seconds": ACTIVE_THREAT_WINDOW,
        "detection_rate": f"{detection_rate_value}%",
        "detection_rate_value": detection_rate_value,
        "detection_rate_definition": "total_alerts / total_packets (lifetime)",
        "attack_types": attack_types,
        "severity_distribution": severity_dist,
        "top_attackers": top_attackers,
    }

def clear_all_data():
    """Clears all stored alerts, packet logs, and resets statistics."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM packet_logs")
    cursor.execute("UPDATE traffic_stats SET total_packets = 0, total_bytes = 0, total_alerts = 0 WHERE id = 1")
    conn.commit()
    conn.close()
    logger.info("Database reset: cleared alerts and stats.")
