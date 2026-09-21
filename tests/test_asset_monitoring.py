"""
Asset IP Monitoring tests.

Covers: asset filter modes + validation, asset-scoped detection routing (using real
Scapy packet objects), evidence fields, duplicate suppression, flow aggregation,
capture-state machine, resolve/metrics, and the monitor REST API.
"""
import time

import pytest
from scapy.all import IP, TCP, Ether

from Backend.asset_filter import AssetFilter
from Backend.detector import IntrusionDetector
from Backend.models import Packet
from Backend.sniffer import NetworkSniffer, STATE_LIVE, STATE_NO_TRAFFIC, STATE_STOPPED, STATE_DISCONNECTED, STATE_PERMISSION_DENIED


def _pkt(src, dst, dport, flags="S", proto="TCP", ts=None, sport=40000):
    return Packet(source_ip=src, destination_ip=dst, source_port=sport,
                  destination_port=dport, protocol=proto,
                  timestamp=ts if ts is not None else time.time(), length=64, flags=flags)


# --- AssetFilter ---

def test_filter_both_mode():
    f = AssetFilter("192.168.1.50", "BOTH")
    assert f.enabled
    assert f.matches(_pkt("10.0.0.1", "192.168.1.50", 80))   # inbound
    assert f.matches(_pkt("192.168.1.50", "10.0.0.1", 80))   # outbound
    assert not f.matches(_pkt("10.0.0.1", "10.0.0.2", 80))   # unrelated


def test_filter_inbound_mode():
    f = AssetFilter("192.168.1.50", "INBOUND")
    assert f.matches(_pkt("10.0.0.1", "192.168.1.50", 80))
    assert not f.matches(_pkt("192.168.1.50", "10.0.0.1", 80))


def test_filter_outbound_mode():
    f = AssetFilter("192.168.1.50", "OUTBOUND")
    assert f.matches(_pkt("192.168.1.50", "10.0.0.1", 80))
    assert not f.matches(_pkt("10.0.0.1", "192.168.1.50", 80))


def test_filter_disabled_matches_all():
    f = AssetFilter("", "BOTH")
    assert not f.enabled
    assert f.matches(_pkt("1.2.3.4", "5.6.7.8", 80))


def test_filter_rejects_invalid_ip():
    with pytest.raises(ValueError):
        AssetFilter("not-an-ip", "BOTH")


def test_filter_rejects_invalid_mode():
    with pytest.raises(ValueError):
        AssetFilter("192.168.1.50", "SIDEWAYS")


# --- Asset-scoped detection with evidence ---

def test_asset_port_scan_evidence():
    d = IntrusionDetector(port_scan_threshold=5, port_scan_window=10)
    now = time.time()
    alert = None
    for i, port in enumerate([22, 23, 25, 53, 80]):
        a = d.analyze_packet(_pkt("10.10.10.25", "192.168.1.50", port, ts=now + i * 0.1, sport=50000 + i),
                             asset_ip="192.168.1.50")
        if a:
            alert = a
    assert alert is not None
    assert alert.attack_type == "PORT_SCAN"
    assert alert.asset_ip == "192.168.1.50"
    assert alert.source_ip == "10.10.10.25"
    assert alert.destination_ip == "192.168.1.50"
    ev = alert.evidence
    assert ev["unique_ports"] == 5
    assert ev["ports"] == [22, 23, 25, 53, 80]
    assert ev["packet_count"] == 5
    assert ev["window_seconds"] == 10
    assert ev["threshold"] == 5
    assert alert.first_seen <= alert.last_seen


def test_asset_single_connection_not_scan():
    d = IntrusionDetector(port_scan_threshold=5, port_scan_window=10)
    assert d.analyze_packet(_pkt("10.10.10.25", "192.168.1.50", 22), asset_ip="192.168.1.50") is None


def test_asset_syn_flood_evidence_and_rate():
    d = IntrusionDetector(syn_flood_threshold=10, syn_flood_window=5, syn_flood_rate_threshold=0)
    now = time.time()
    alert = None
    for i in range(15):
        a = d.analyze_packet(_pkt("10.10.10.25", "192.168.1.50", 80, ts=now + i * 0.05, sport=30000 + i),
                             asset_ip="192.168.1.50")
        if a:
            alert = a
    assert alert is not None and alert.attack_type == "SYN_FLOOD"
    ev = alert.evidence
    assert ev["syn_count"] >= 10
    assert ev["window_seconds"] == 5
    assert ev["observed_rate_per_sec"] > 0


def test_asset_syn_flood_rate_threshold_blocks_slow_burst():
    # 10 SYNs over 10s = 1/s; rate threshold 5/s must NOT fire.
    d = IntrusionDetector(syn_flood_threshold=10, syn_flood_window=10, syn_flood_rate_threshold=5.0)
    now = time.time()
    alert = None
    for i in range(10):
        a = d.analyze_packet(_pkt("10.10.10.25", "192.168.1.50", 80, ts=now + i * 1.0, sport=30000 + i),
                             asset_ip="192.168.1.50")
        if a:
            alert = a
    assert alert is None


def test_asset_suspicious_port_evidence():
    d = IntrusionDetector(suspicious_ports={4444: {"severity": "HIGH", "label": "Metasploit Default"}})
    alert = d.analyze_packet(_pkt("10.10.10.25", "192.168.1.50", 4444), asset_ip="192.168.1.50")
    assert alert is not None and alert.attack_type == "SUSPICIOUS_PORT"
    assert alert.evidence["reason"] == "Metasploit Default"
    assert alert.evidence["port"] == 4444
    assert alert.asset_ip == "192.168.1.50"


def test_no_duplicate_alerts_for_ongoing_event():
    d = IntrusionDetector(port_scan_threshold=5, port_scan_window=10, cooldown_period=15)
    now = time.time()
    port_scan_alerts = 0
    for i in range(40):
        a = d.analyze_packet(_pkt("10.10.10.25", "192.168.1.50", 1000 + (i % 12), ts=now + i * 0.05, sport=50000 + i),
                             asset_ip="192.168.1.50")
        if a and a.attack_type == "PORT_SCAN":
            port_scan_alerts += 1
    # One PORT_SCAN alert per cooldown window, not one per packet.
    assert port_scan_alerts == 1


# --- Sniffer routing with REAL Scapy packets ---

def _scapy_pkt(src, dst, dport, sport=40000, flags="S"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def test_sniffer_asset_routing_only_matching_packets_detected():
    from Backend.database import init_db, clear_all_data
    init_db(); clear_all_data()
    try:
        detector = IntrusionDetector(port_scan_threshold=4, port_scan_window=10)
        sniffer = NetworkSniffer(detector=detector)
        sniffer.is_running = True  # simulate running capture without touching the NIC
        sniffer.start_monitoring("192.168.1.50", "BOTH")

        now = time.time()
        # 6 packets TO the asset on distinct ports -> should trigger PORT_SCAN
        for i, port in enumerate([22, 23, 25, 53, 80, 443]):
            sniffer._handle_scapy_packet(_scapy_pkt("10.10.10.25", "192.168.1.50", port, sport=50000 + i))
        # 6 packets NOT involving the asset -> must be ignored by detection
        for i, port in enumerate([22, 23, 25, 53, 80, 443]):
            sniffer._handle_scapy_packet(_scapy_pkt("10.9.9.9", "10.8.8.8", port, sport=51000 + i))

        status = sniffer.get_monitor_status()
        assert status["asset"]["asset_ip"] == "192.168.1.50"
        assert status["asset_packets_observed"] == 6  # only asset-relevant counted
        assert status["packets_observed"] == 12       # all captured counted
        assert status["flows_total"] == 6

        alerts = _db_alerts()
        port_scans = [a for a in alerts if a["attack_type"] == "PORT_SCAN"]
        assert len(port_scans) == 1
        assert port_scans[0]["asset_ip"] == "192.168.1.50"
        assert port_scans[0]["source_ip"] == "10.10.10.25"
    finally:
        clear_all_data()


def _db_alerts():
    from Backend.database import get_all_alerts
    return get_all_alerts(limit=100)


# --- Flow aggregation ---

def test_flow_aggregation_distinct_tuples():
    detector = IntrusionDetector()
    sniffer = NetworkSniffer(detector=detector)
    now = time.time()
    sniffer._track_flow(_pkt("1.1.1.1", "2.2.2.2", 80, sport=1000), now)
    sniffer._track_flow(_pkt("1.1.1.1", "2.2.2.2", 80, sport=1000), now + 0.1)  # same flow
    sniffer._track_flow(_pkt("1.1.1.1", "2.2.2.2", 443, sport=1001), now + 0.2)  # new flow
    assert sniffer.flows_total == 2
    assert sniffer.active_flows() == 2


# --- Capture state machine ---

def test_capture_state_transitions():
    detector = IntrusionDetector()
    sniffer = NetworkSniffer(detector=detector)
    assert sniffer.current_capture_state() == STATE_STOPPED  # not running

    sniffer.is_running = True
    sniffer._capture_verified = False
    assert sniffer.current_capture_state() == "INITIALIZING"

    sniffer._capture_verified = True
    sniffer._last_packet_time = None
    assert sniffer.current_capture_state() == STATE_NO_TRAFFIC

    sniffer._last_packet_time = time.time()
    assert sniffer.current_capture_state() == STATE_LIVE

    sniffer._last_packet_time = time.time() - 999
    assert sniffer.current_capture_state() == STATE_NO_TRAFFIC

    sniffer._thread_died = True
    assert sniffer.current_capture_state() == STATE_DISCONNECTED

    sniffer._capture_state = STATE_PERMISSION_DENIED
    assert sniffer.current_capture_state() == STATE_PERMISSION_DENIED


def test_demo_does_not_fake_liveness():
    detector = IntrusionDetector()
    sniffer = NetworkSniffer(detector=detector)
    sniffer.trigger_demo_port_scan()  # simulation must not set last_packet_time
    assert sniffer._last_packet_time is None
    assert sniffer.current_capture_state() == STATE_STOPPED


# --- Monitor REST API ---

def test_monitor_api_start_stop_and_validation():
    from Backend.app import app
    from Backend.database import init_db, clear_all_data
    init_db(); clear_all_data()
    app.config["TESTING"] = True
    with app.test_client() as c:
        # invalid IP rejected
        r = c.post("/api/monitor/start", json={"asset_ip": "bad", "mode": "BOTH"})
        assert r.status_code == 400
        # missing IP rejected
        r = c.post("/api/monitor/start", json={})
        assert r.status_code == 400
        # valid start
        r = c.post("/api/monitor/start", json={"asset_ip": "192.168.1.50", "mode": "INBOUND"})
        assert r.status_code == 200
        st = c.get("/api/monitor/status").get_json()
        assert st["asset"]["asset_ip"] == "192.168.1.50"
        assert st["asset"]["mode"] == "INBOUND"
        # stop
        r = c.post("/api/monitor/stop")
        assert r.status_code == 200
        st = c.get("/api/monitor/status").get_json()
        assert st["asset"]["enabled"] is False
        clear_all_data()


def test_resolve_alert_removes_from_active():
    from Backend.database import init_db, clear_all_data, save_alert, get_stats, resolve_alert
    init_db(); clear_all_data()
    try:
        aid = save_alert({"attack_type": "PORT_SCAN", "severity": "HIGH", "confidence": 0.9,
                          "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                          "asset_ip": "10.0.0.2", "evidence": {"unique_ports": 8}})
        assert get_stats()["active_alerts"] == 1
        assert resolve_alert(aid) is True
        stats = get_stats()
        assert stats["resolved_alerts"] == 1
        assert stats["active_alerts"] == 0  # resolved no longer active
    finally:
        clear_all_data()
