"""
Focused detection-quality, metric, and robustness tests for the NIDS engine.

Covers: normal traffic, single connection, port scan, SYN flood, suspicious port,
duplicate/cooldown handling, expired windows, malformed packets, empty traffic,
high volume, simultaneous sources, metric calculation, and severity calculation.
"""
import time

from Backend.detector import IntrusionDetector
from Backend.models import Packet


def _pkt(src, dst, dport, flags="", proto="TCP", ts=None, sport=40000):
    return Packet(
        source_ip=src,
        destination_ip=dst,
        source_port=sport,
        destination_port=dport,
        protocol=proto,
        timestamp=ts if ts is not None else time.time(),
        length=64,
        flags=flags,
    )


# --- Normal traffic / single connection ---

def test_single_connection_is_not_port_scan():
    """One connection to one port must never be classified as a port scan."""
    d = IntrusionDetector(port_scan_threshold=8, port_scan_window=10)
    now = time.time()
    alert = d.analyze_packet(_pkt("192.168.1.5", "10.0.0.1", 443, "S", ts=now))
    assert alert is None


def test_normal_web_browsing_no_alerts():
    """Repeated connections to a small set of common ports at a human rate stay quiet."""
    d = IntrusionDetector(port_scan_threshold=8, port_scan_window=10)
    now = time.time()
    alerts = []
    # 0.5s spacing keeps <30 SYNs in any 5s window (no SYN flood) and only 2 unique ports.
    for i in range(50):
        port = [80, 443][i % 2]
        a = d.analyze_packet(_pkt("192.168.1.5", "10.0.0.1", port, "S", ts=now + i * 0.5, sport=40000 + i))
        if a:
            alerts.append(a)
    assert alerts == []


def test_empty_traffic_no_state_no_alert():
    """No packets => no alerts and no accumulated state."""
    d = IntrusionDetector()
    assert d.analyze_packet is not None
    assert len(d.port_history) == 0
    assert len(d.syn_history) == 0


# --- Port scan ---

def test_port_scan_triggers_at_threshold():
    d = IntrusionDetector(port_scan_threshold=8, port_scan_window=10)
    now = time.time()
    alert = None
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 443]):
        a = d.analyze_packet(_pkt("192.168.1.50", "10.0.0.5", port, "S", ts=now + i * 0.1, sport=50000 + i))
        if a:
            alert = a
    assert alert is not None
    assert alert.attack_type == "PORT_SCAN"
    assert alert.source_ip == "192.168.1.50"
    assert alert.destination_ip == "10.0.0.5"


def test_port_scan_duplicate_ports_do_not_count():
    """Repeated hits to the SAME port are not a scan (unique-port counting)."""
    d = IntrusionDetector(port_scan_threshold=8, port_scan_window=10)
    now = time.time()
    alert = None
    for i in range(20):
        a = d.analyze_packet(_pkt("192.168.1.50", "10.0.0.5", 80, "S", ts=now + i * 0.1, sport=50000 + i))
        if a:
            alert = a
    assert alert is None


def test_port_scan_severity_is_high():
    """PORT_SCAN is a deterministic HIGH-severity reconnaissance classification."""
    d = IntrusionDetector(port_scan_threshold=8, port_scan_window=10)
    now = time.time()
    alert = None
    for i, port in enumerate(range(1000, 1008)):
        a = d.analyze_packet(_pkt("10.1.1.1", "10.0.0.9", port, "S", ts=now + i * 0.05, sport=60000 + i))
        if a:
            alert = a
    assert alert is not None
    assert alert.attack_type == "PORT_SCAN"
    assert alert.severity == "HIGH"


def test_syn_flood_severity_is_critical():
    """SYN_FLOOD is an availability attack and is deterministically CRITICAL."""
    d = IntrusionDetector(syn_flood_threshold=10, syn_flood_window=5)
    now = time.time()
    alert = None
    for i in range(15):
        a = d.analyze_packet(_pkt("10.7.7.7", "192.168.1.10", 80, "S", ts=now + i * 0.05, sport=62000 + i))
        if a:
            alert = a
    assert alert is not None
    assert alert.severity == "CRITICAL"


# --- Expired windows ---

def test_port_scan_window_expiry():
    """Ports spread beyond the window do not accumulate into a scan."""
    d = IntrusionDetector(port_scan_threshold=8, port_scan_window=2)
    now = time.time()
    port_scan_alert = None
    # 8 ports, 1 second apart over 8s; window is 2s so never 8 concurrent.
    # Ports are chosen to avoid the suspicious-port list so we isolate the PORT_SCAN rule.
    for i, port in enumerate([5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008]):
        a = d.analyze_packet(_pkt("192.168.1.77", "10.0.0.7", port, "S", ts=now + i * 1.0, sport=52000 + i))
        if a and a.attack_type == "PORT_SCAN":
            port_scan_alert = a
    assert port_scan_alert is None


def test_syn_flood_window_expiry():
    """SYNs spread out beyond the window never reach the threshold."""
    d = IntrusionDetector(syn_flood_threshold=10, syn_flood_window=1)
    now = time.time()
    alert = None
    for i in range(40):
        a = d.analyze_packet(_pkt("10.9.9.9", "10.0.0.1", 80, "S", ts=now + i * 0.5, sport=30000 + i))
        if a:
            alert = a
    assert alert is None


# --- SYN flood ---

def test_syn_flood_triggers_on_genuine_syns():
    d = IntrusionDetector(syn_flood_threshold=30, syn_flood_window=5)
    now = time.time()
    alert = None
    for i in range(35):
        a = d.analyze_packet(_pkt("10.0.0.88", "192.168.1.10", 80, "S", ts=now + i * 0.02, sport=10000 + i))
        if a:
            alert = a
    assert alert is not None
    assert alert.attack_type == "SYN_FLOOD"
    assert alert.severity == "CRITICAL"


def test_syn_ack_replies_are_not_a_flood():
    """Server SYN-ACK responses must NOT be counted as a SYN flood (false-positive guard)."""
    d = IntrusionDetector(syn_flood_threshold=30, syn_flood_window=5)
    now = time.time()
    alert = None
    for i in range(100):
        a = d.analyze_packet(_pkt("192.168.1.10", "10.0.0.88", 80, "SA", ts=now + i * 0.01, sport=11000 + i))
        if a and a.attack_type == "SYN_FLOOD":
            alert = a
    assert alert is None


def test_syn_flood_cooldown_prevents_duplicates():
    """A sustained flood yields one alert per cooldown period, not one per packet."""
    d = IntrusionDetector(syn_flood_threshold=10, syn_flood_window=5, cooldown_period=15)
    now = time.time()
    syn_alerts = 0
    for i in range(200):
        a = d.analyze_packet(_pkt("10.5.5.5", "192.168.1.10", 80, "S", ts=now + i * 0.01, sport=20000 + i))
        if a and a.attack_type == "SYN_FLOOD":
            syn_alerts += 1
    # 200 packets over 2 seconds is well within one 15s cooldown -> exactly 1 alert
    assert syn_alerts == 1


# --- Suspicious port ---

def test_suspicious_port_uses_configured_list():
    d = IntrusionDetector(suspicious_ports={4444: {"severity": "HIGH", "label": "Metasploit Default"}})
    now = time.time()
    alert = d.analyze_packet(_pkt("10.2.2.2", "192.168.1.10", 4444, "S", ts=now))
    assert alert is not None
    assert alert.attack_type == "SUSPICIOUS_PORT"
    assert alert.severity == "HIGH"
    assert alert.destination_port == 4444
    assert "Metasploit Default" in alert.details


def test_unlisted_port_is_not_suspicious():
    """An unusual but unconfigured port must not be auto-classified as malicious."""
    d = IntrusionDetector(suspicious_ports={4444: {"severity": "HIGH", "label": "x"}})
    now = time.time()
    alert = d.analyze_packet(_pkt("10.2.2.2", "192.168.1.10", 54321, "S", ts=now))
    assert alert is None


def test_suspicious_port_cooldown():
    d = IntrusionDetector(suspicious_ports={23: {"severity": "MEDIUM", "label": "Telnet"}}, cooldown_period=15)
    now = time.time()
    count = 0
    for i in range(20):
        a = d.analyze_packet(_pkt("10.2.2.3", "192.168.1.10", 23, "S", ts=now + i * 0.1, sport=33000 + i))
        if a and a.attack_type == "SUSPICIOUS_PORT":
            count += 1
    assert count == 1


# --- Malformed / adversarial packets ---

def test_malformed_packet_does_not_crash():
    """Garbage field values must be handled safely without raising."""
    d = IntrusionDetector()
    weird = Packet(
        source_ip=None,
        destination_ip=None,
        source_port=None,
        destination_port=None,
        protocol=None,
        timestamp="not-a-number",  # invalid timestamp
        length=0,
        flags=None,
    )
    # Should not raise
    assert d.analyze_packet(weird) is None


def test_missing_destination_port_skipped():
    d = IntrusionDetector()
    assert d.analyze_packet(_pkt("1.1.1.1", "2.2.2.2", 0, "S")) is None


# --- Simultaneous sources ---

def test_simultaneous_sources_tracked_independently():
    """Two scanning sources are detected independently without cross-talk."""
    d = IntrusionDetector(port_scan_threshold=5, port_scan_window=10)
    now = time.time()
    a_alert = b_alert = None
    for i in range(6):
        a = d.analyze_packet(_pkt("10.0.0.1", "192.168.1.10", 3000 + i, "S", ts=now + i * 0.1, sport=44000 + i))
        b = d.analyze_packet(_pkt("10.0.0.2", "192.168.1.10", 3000 + i, "S", ts=now + i * 0.1, sport=45000 + i))
        if a and a.source_ip == "10.0.0.1":
            a_alert = a
        if b and b.source_ip == "10.0.0.2":
            b_alert = b
    assert a_alert is not None and b_alert is not None
    assert a_alert.source_ip != b_alert.source_ip


# --- High volume ---

def test_high_volume_does_not_leak_state():
    """After a burst, stale-key pruning keeps detector state bounded."""
    d = IntrusionDetector(port_scan_threshold=1000, port_scan_window=1)
    d._prune_interval = 0  # force pruning every call
    base = time.time()
    # 5000 packets from 500 distinct sources, all in the past relative to final ts
    t = base
    for i in range(5000):
        src = f"10.0.{i % 500}.1"
        t = base + i * 0.001
        d.analyze_packet(_pkt(src, "192.168.1.10", 80, "S", ts=t, sport=50000 + (i % 1000)))
    # Final packet far in the future triggers eviction of all stale keys
    d.analyze_packet(_pkt("10.0.0.1", "192.168.1.10", 80, "S", ts=t + 60))
    assert len(d.syn_history) <= 2


# --- Metric calculation ---

def test_metric_detection_rate_and_active_threats():
    """get_stats math: detection_rate = alerts/packets; active_threats is windowed."""
    from Backend.database import init_db, clear_all_data, save_alert, increment_packet_count, get_stats

    init_db()
    clear_all_data()
    try:
        increment_packet_count(count=200, total_bytes=12800)
        save_alert({"attack_type": "PORT_SCAN", "severity": "HIGH", "confidence": 0.9,
                    "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2"})
        save_alert({"attack_type": "SYN_FLOOD", "severity": "CRITICAL", "confidence": 0.95,
                    "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2"})
        stats = get_stats()
        assert stats["total_packets"] == 200
        assert stats["total_alerts"] == 2
        assert stats["total_attacks"] == 2
        assert stats["detection_rate_value"] == 1.0  # 2/200 * 100
        assert stats["attack_types"]["PORT_SCAN"] == 1
        assert stats["severity_distribution"]["CRITICAL"] == 1
        # Fresh alerts fall inside the active window
        assert stats["active_threats"] == 2
    finally:
        clear_all_data()


def test_active_threats_excludes_old_alerts():
    """Alerts older than the window are historical, not active."""
    from Backend.database import init_db, clear_all_data, save_alert, get_stats
    from datetime import datetime, timedelta, timezone

    init_db()
    clear_all_data()
    try:
        old_ts = (datetime.now(timezone.utc) - timedelta(seconds=99999)).isoformat()
        save_alert({"attack_type": "PORT_SCAN", "severity": "HIGH", "confidence": 0.9,
                    "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "timestamp": old_ts})
        stats = get_stats()
        assert stats["total_attacks"] == 1
        assert stats["active_threats"] == 0
    finally:
        clear_all_data()


def test_detection_rate_zero_packets_is_safe():
    """No divide-by-zero when no packets have been seen."""
    from Backend.database import init_db, clear_all_data, get_stats
    init_db()
    clear_all_data()
    try:
        stats = get_stats()
        assert stats["total_packets"] == 0
        assert stats["detection_rate_value"] == 0.0
    finally:
        clear_all_data()
