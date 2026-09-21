import sqlite3
import logging
from datetime import datetime, timedelta, timezone
import os
from .config import DB_PATH

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
            status TEXT DEFAULT 'ACTIVE'
        )
    """)

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
            (timestamp, attack_type, severity, confidence, source_ip, destination_ip, source_port, destination_port, protocol, details, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            alert_data.get("status", "ACTIVE")
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
    return [dict(row) for row in rows]

def get_stats():
    """Retrieves cumulative and real-time dashboard analytics statistics."""
    conn = get_connection()
    cursor = conn.cursor()

    # Get overall counts
    cursor.execute("SELECT total_packets, total_bytes, total_alerts FROM traffic_stats WHERE id = 1")
    stat_row = cursor.fetchone()
    total_packets = stat_row["total_packets"] if stat_row else 0
    total_bytes = stat_row["total_bytes"] if stat_row else 0
    total_alerts = stat_row["total_alerts"] if stat_row else 0

    # Active threats (alerts with status ACTIVE)
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'ACTIVE'")
    active_threats = cursor.fetchone()[0]

    # Total Attacks count
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

    # Detection Rate calculation (Alerts / Total Packets or percentage)
    detection_rate = round((total_alerts / max(total_packets, 1)) * 100, 2)

    conn.close()
    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_alerts": total_alerts,
        "total_attacks": total_attacks,
        "active_threats": active_threats,
        "detection_rate": f"{detection_rate}%",
        "attack_types": attack_types,
        "severity_distribution": severity_dist,
        "top_attackers": top_attackers
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
