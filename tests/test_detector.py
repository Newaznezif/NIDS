import pytest
import time
from Backend.models import Packet
from Backend.detector import IntrusionDetector

def test_port_scan_detection_triggered():
    """Verify PORT_SCAN alert is generated when >= 8 unique destination ports are probed within window."""
    detector = IntrusionDetector(port_scan_threshold=8, port_scan_window=10)
    source_ip = "192.168.1.100"
    target_ip = "192.168.1.10"
    
    ports = [21, 22, 23, 25, 53, 80, 110, 443] # 8 unique ports
    alert = None
    now = time.time()

    for i, p in enumerate(ports):
        pkt = Packet(
            source_ip=source_ip,
            destination_ip=target_ip,
            source_port=50000 + i,
            destination_port=p,
            protocol="TCP",
            timestamp=now + (i * 0.1)
        )
        res = detector.analyze_packet(pkt)
        if res:
            alert = res

    assert alert is not None
    assert alert.attack_type == "PORT_SCAN"
    assert alert.severity == "HIGH"
    assert alert.source_ip == source_ip
    assert alert.destination_ip == target_ip

def test_port_scan_below_threshold_no_alert():
    """Verify NO alert is triggered when unique destination ports probed is below threshold (< 8)."""
    detector = IntrusionDetector(port_scan_threshold=8, port_scan_window=10)
    source_ip = "192.168.1.200"
    target_ip = "192.168.1.10"

    ports = [80, 443, 8080, 8443, 3000] # Only 5 unique ports
    alert = None
    now = time.time()

    for i, p in enumerate(ports):
        pkt = Packet(
            source_ip=source_ip,
            destination_ip=target_ip,
            source_port=40000 + i,
            destination_port=p,
            protocol="TCP",
            timestamp=now + (i * 0.1)
        )
        res = detector.analyze_packet(pkt)
        if res:
            alert = res

    assert alert is None

def test_syn_flood_detection_triggered():
    """Verify SYN_FLOOD alert is triggered on high frequency SYN packets."""
    detector = IntrusionDetector()
    source_ip = "10.0.0.99"
    target_ip = "192.168.1.10"
    now = time.time()
    alert = None

    for i in range(35): # Above threshold 30
        pkt = Packet(
            source_ip=source_ip,
            destination_ip=target_ip,
            source_port=10000 + i,
            destination_port=80,
            protocol="TCP",
            flags="S",
            timestamp=now + (i * 0.02)
        )
        res = detector.analyze_packet(pkt)
        if res:
            alert = res

    assert alert is not None
    assert alert.attack_type == "SYN_FLOOD"
    assert alert.severity == "CRITICAL"
