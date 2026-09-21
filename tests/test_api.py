import pytest
import json
from Backend.app import app
from Backend.database import init_db, clear_all_data

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            init_db()
            clear_all_data()
        yield client
        with app.app_context():
            clear_all_data()

def test_health_endpoint(client):
    """GET /api/health should return 200 and healthy status."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert "mode" in data

def test_stats_endpoint(client):
    """GET /api/stats should return dashboard statistics."""
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_attacks" in data
    assert "active_threats" in data

def test_alerts_endpoint(client):
    """GET /api/alerts should return list of alerts."""
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)

def test_demo_attack_endpoint(client):
    """POST /api/demo/attack should execute port scan through detection pipeline and store alert."""
    payload = {
        "attack_type": "PORT_SCAN",
        "source_ip": "192.168.1.99",
        "target_ip": "192.168.1.10",
        "ports_count": 10
    }
    res = client.post(
        "/api/demo/attack",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert res.status_code == 200
    data = res.get_json()
    assert "result" in data
    assert data["result"]["alerts_triggered"] >= 1

    # Verify alert was saved in DB via GET /api/alerts
    res_alerts = client.get("/api/alerts")
    alerts_data = res_alerts.get_json()
    assert alerts_data["count"] >= 1
    assert alerts_data["alerts"][0]["attack_type"] == "PORT_SCAN"

def test_clear_endpoint(client):
    """POST /api/clear should reset DB and stats."""
    # Insert an alert first
    client.post("/api/demo/attack", data=json.dumps({"attack_type": "PORT_SCAN"}), content_type="application/json")
    
    # Clear data
    res_clear = client.post("/api/clear")
    assert res_clear.status_code == 200

    # Verify 0 alerts
    res_alerts = client.get("/api/alerts")
    assert res_alerts.get_json()["count"] == 0
