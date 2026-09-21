import threading
import time
import logging
import random
from typing import Dict, Any, Optional

from .config import DEFAULT_INTERFACE, PORT_SCAN_THRESHOLD
from .analyzer import PacketAnalyzer, SCAPY_AVAILABLE
from .detector import IntrusionDetector
from .alert_engine import process_alert
from .database import save_packet, increment_packet_count

logger = logging.getLogger("NIDS.Sniffer")

try:
    from scapy.all import sniff, get_if_list, conf # type: ignore
except Exception:
    sniff = None
    get_if_list = None

class NetworkSniffer:
    """
    Manages live packet sniffing via Scapy in a background thread,
    with automatic fallback to DEMO mode if live sniffing is unavailable.
    """

    def __init__(self, detector: IntrusionDetector):
        self.detector = detector
        self.is_running = False
        self.mode = "INITIALIZING" # "LIVE", "DEMO", "UNAVAILABLE"
        self.interface = DEFAULT_INTERFACE
        self.thread: Optional[threading.Thread] = None
        self.packets_count = 0
        self.bytes_count = 0
        self.error_message = None

    def start(self):
        """Attempts to start live sniffing; falls back to DEMO mode on Windows/permission failure."""
        self.is_running = True
        
        if not SCAPY_AVAILABLE or sniff is None:
            self.mode = "DEMO"
            self.error_message = "Scapy or WinPcap/Npcap missing. Running in DEMO mode."
            logger.warning(f"[SNIFFER] {self.error_message}")
            return

        # Start live sniffer thread
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        logger.info("[SNIFFER] Background sniffing thread launched.")

    def _sniff_loop(self):
        """Background worker thread for Scapy sniff()."""
        try:
            logger.info("Initializing network interface packet capture...")
            # Test sniffing a single packet to verify WinPcap/Npcap permissions
            self.mode = "LIVE"
            sniff(count=1, store=False, timeout=2)
            logger.info("[SNIFFER] Live capture successfully verified.")

            # Continuous sniff loop
            while self.is_running:
                sniff(
                    iface=self.interface,
                    prn=self._handle_scapy_packet,
                    store=False,
                    count=10,
                    timeout=1
                )
        except Exception as e:
            self.mode = "DEMO"
            self.error_message = f"Live capture failed ({type(e).__name__}: {e}). Switched to DEMO mode."
            logger.warning(f"[SNIFFER] Live sniffing error: {e}. Defaulting to DEMO mode.")

    def _handle_scapy_packet(self, scapy_pkt):
        """Processes each captured raw packet."""
        if not self.is_running:
            return

        packet = PacketAnalyzer.parse_scapy_packet(scapy_pkt)
        if not packet:
            return

        self.packets_count += 1
        self.bytes_count += packet.length
        increment_packet_count(count=1, total_bytes=packet.length)

        # Run through detection engine
        alert = self.detector.analyze_packet(packet)
        if alert:
            process_alert(alert)

    def trigger_demo_port_scan(self, source_ip: str = "192.168.1.100", target_ip: str = "192.168.1.10", ports_count: int = 10) -> Dict[str, Any]:
        """
        Simulates controlled network traffic representing a Port Scan.
        Pushes packets sequentially through Analyzer -> Detector -> Alert Engine -> Database.
        """
        logger.info(f"[DEMO ATTACK] Simulating Port Scan from {source_ip} -> {target_ip} ({ports_count} ports)")
        
        target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 8080, 8443][:ports_count]
        generated_alerts = []

        now = time.time()
        for i, port in enumerate(target_ports):
            pkt_dict = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(49152, 65535),
                "destination_port": port,
                "protocol": "TCP",
                "timestamp": now + (i * 0.1), # rapid requests within window
                "length": random.randint(54, 128),
                "flags": "S" # SYN flag for port probe
            }

            packet = PacketAnalyzer.parse_dict_packet(pkt_dict)
            self.packets_count += 1
            self.bytes_count += packet.length
            save_packet(pkt_dict)

            alert = self.detector.analyze_packet(packet)
            if alert:
                alert_payload = process_alert(alert)
                generated_alerts.append(alert_payload)

        return {
            "status": "success",
            "packets_generated": len(target_ports),
            "alerts_triggered": len(generated_alerts),
            "alerts": generated_alerts
        }

    def trigger_demo_syn_flood(self, source_ip: str = "10.0.0.88", target_ip: str = "192.168.1.10", count: int = 35) -> Dict[str, Any]:
        """Simulates SYN Flood attack vector."""
        logger.info(f"[DEMO ATTACK] Simulating SYN Flood from {source_ip} -> {target_ip}")
        generated_alerts = []
        now = time.time()

        for i in range(count):
            pkt_dict = {
                "source_ip": source_ip,
                "destination_ip": target_ip,
                "source_port": random.randint(1024, 65535),
                "destination_port": 80,
                "protocol": "TCP",
                "timestamp": now + (i * 0.05),
                "length": 64,
                "flags": "S"
            }
            packet = PacketAnalyzer.parse_dict_packet(pkt_dict)
            self.packets_count += 1
            self.bytes_count += packet.length
            save_packet(pkt_dict)

            alert = self.detector.analyze_packet(packet)
            if alert:
                alert_payload = process_alert(alert)
                generated_alerts.append(alert_payload)

        return {
            "status": "success",
            "packets_generated": count,
            "alerts_triggered": len(generated_alerts),
            "alerts": generated_alerts
        }

    def stop(self):
        """Stops the sniffer background loop."""
        self.is_running = False
        self.mode = "STOPPED"

    def get_status_info(self) -> Dict[str, Any]:
        return {
            "mode": self.mode, # LIVE, DEMO, UNAVAILABLE
            "is_running": self.is_running,
            "interface": self.interface or "Auto/Default",
            "packets_captured": self.packets_count,
            "bytes_captured": self.bytes_count,
            "error_message": self.error_message
        }
