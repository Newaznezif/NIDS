import pytest
import os
from Backend.database import init_db, save_alert, get_all_alerts, get_stats, clear_all_data

@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensures DB is initialized and clean for each test."""
    init_db()
    clear_all_data()
    yield
    clear_all_data()

def test_db_initialization():
    """Verify database schema creation and default stats."""
    stats = get_stats()
    assert isinstance(stats, dict)
    assert "total_packets" in stats
    assert "total_alerts" in stats

def test_save_and_retrieve_alert():
    """Verify alert persistence and retrieval."""
    alert_payload = {
        "attack_type": "PORT_SCAN",
        "severity": "HIGH",
        "confidence": 0.92,
        "source_ip": "172.16.0.50",
        "destination_ip": "172.16.0.1",
        "source_port": 54321,
        "destination_port": 80,
        "protocol": "TCP",
        "details": "Test Port Scan event",
        "status": "ACTIVE"
    }

    alert_id = save_alert(alert_payload)
    assert alert_id is not None

    alerts = get_all_alerts()
    assert len(alerts) >= 1
    retrieved = alerts[0]
    assert retrieved["attack_type"] == "PORT_SCAN"
    assert retrieved["source_ip"] == "172.16.0.50"

def test_stats_aggregation():
    """Verify that saving alerts updates overall statistics counters."""
    save_alert({
        "attack_type": "SYN_FLOOD",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.1"
    })

    stats = get_stats()
    assert stats["total_alerts"] >= 1
    assert stats["total_attacks"] >= 1
    assert "SYN_FLOOD" in stats["attack_types"]
