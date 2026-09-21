import time
import logging
from collections import defaultdict
from typing import Optional, List, Dict, Set
from .models import Packet, Alert
from .config import PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW, SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW

logger = logging.getLogger("NIDS.Detector")

class IntrusionDetector:
    """Stateful rule-based intrusion detection engine."""

    def __init__(self, port_scan_threshold: int = PORT_SCAN_THRESHOLD, port_scan_window: float = PORT_SCAN_WINDOW):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        
        # State tracking for Port Scan: (src_ip, dst_ip) -> list of (dst_port, timestamp)
        self.port_history: Dict[tuple, List[tuple]] = defaultdict(list)
        
        # Cooldown tracking to prevent alert flood: (src_ip, dst_ip, attack_type) -> last_alert_timestamp
        self.alert_cooldowns: Dict[tuple, float] = {}
        self.cooldown_period = 15.0 # seconds before triggering repeated alert for same src/dst

        # State tracking for SYN Flood: (src_ip) -> list of timestamps
        self.syn_history: Dict[str, List[float]] = defaultdict(list)

    def analyze_packet(self, packet: Packet) -> Optional[Alert]:
        """
        Analyzes an incoming packet against active detection rules.
        Returns an Alert object if an intrusion rule is triggered, otherwise None.
        """
        current_time = packet.timestamp

        # 1. Rule Check: Port Scan Detection
        port_scan_alert = self._check_port_scan(packet, current_time)
        if port_scan_alert:
            return port_scan_alert

        # 2. Rule Check: SYN Flood Detection
        syn_flood_alert = self._check_syn_flood(packet, current_time)
        if syn_flood_alert:
            return syn_flood_alert

        # 3. Rule Check: High Risk Destination Port Probe
        suspicious_port_alert = self._check_suspicious_port(packet, current_time)
        if suspicious_port_alert:
            return suspicious_port_alert

        return None

    def _check_port_scan(self, packet: Packet, current_time: float) -> Optional[Alert]:
        """Tracks destination ports probed by (source_ip, destination_ip) within time window."""
        if not packet.destination_port:
            return None

        key = (packet.source_ip, packet.destination_ip)
        
        # Append current event
        self.port_history[key].append((packet.destination_port, current_time))

        # Filter out events outside the time window
        cutoff = current_time - self.port_scan_window
        self.port_history[key] = [
            (port, ts) for port, ts in self.port_history[key] if ts >= cutoff
        ]

        # Count unique destination ports accessed in window
        unique_ports: Set[int] = {port for port, ts in self.port_history[key]}

        if len(unique_ports) >= self.port_scan_threshold:
            cooldown_key = (packet.source_ip, packet.destination_ip, "PORT_SCAN")
            last_alert = self.alert_cooldowns.get(cooldown_key, 0.0)

            if current_time - last_alert >= self.cooldown_period:
                self.alert_cooldowns[cooldown_key] = current_time
                
                details_str = (
                    f"{len(unique_ports)} unique destination ports probed from "
                    f"{packet.source_ip} to {packet.destination_ip} within {self.port_scan_window}s window. "
                    f"Sample ports: {sorted(list(unique_ports))[:10]}"
                )

                logger.warning(f"[DETECTION] PORT_SCAN detected from {packet.source_ip}: {len(unique_ports)} ports")

                return Alert(
                    attack_type="PORT_SCAN",
                    severity="HIGH",
                    confidence=0.92,
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    source_port=packet.source_port,
                    destination_port=packet.destination_port,
                    protocol=packet.protocol,
                    details=details_str
                )

        return None

    def _check_syn_flood(self, packet: Packet, current_time: float) -> Optional[Alert]:
        """Detects high volume SYN flag requests from a single IP."""
        if packet.protocol != "TCP" or "S" not in packet.flags:
            return None

        src_ip = packet.source_ip
        self.syn_history[src_ip].append(current_time)

        cutoff = current_time - SYN_FLOOD_WINDOW
        self.syn_history[src_ip] = [ts for ts in self.syn_history[src_ip] if ts >= cutoff]

        if len(self.syn_history[src_ip]) >= SYN_FLOOD_THRESHOLD:
            cooldown_key = (src_ip, packet.destination_ip, "SYN_FLOOD")
            last_alert = self.alert_cooldowns.get(cooldown_key, 0.0)

            if current_time - last_alert >= self.cooldown_period:
                self.alert_cooldowns[cooldown_key] = current_time

                return Alert(
                    attack_type="SYN_FLOOD",
                    severity="CRITICAL",
                    confidence=0.95,
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    source_port=packet.source_port,
                    destination_port=packet.destination_port,
                    protocol="TCP",
                    details=f"High frequency SYN flood detected ({len(self.syn_history[src_ip])} SYN packets within {SYN_FLOOD_WINDOW}s)."
                )

        return None

    def _check_suspicious_port(self, packet: Packet, current_time: float) -> Optional[Alert]:
        """Detects probes targeting known backdoor or exploit ports."""
        HIGH_RISK_PORTS = {4444: "Metasploit Default", 31337: "Back Orifice", 6667: "IRC Botnet C2", 23: "Telnet Unencrypted"}
        
        if packet.destination_port in HIGH_RISK_PORTS:
            cooldown_key = (packet.source_ip, packet.destination_ip, f"SUSPICIOUS_PORT_{packet.destination_port}")
            last_alert = self.alert_cooldowns.get(cooldown_key, 0.0)

            if current_time - last_alert >= self.cooldown_period:
                self.alert_cooldowns[cooldown_key] = current_time
                service_name = HIGH_RISK_PORTS[packet.destination_port]

                return Alert(
                    attack_type="SUSPICIOUS_PORT",
                    severity="MEDIUM",
                    confidence=0.85,
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    source_port=packet.source_port,
                    destination_port=packet.destination_port,
                    protocol=packet.protocol,
                    details=f"Connection attempt to high-risk port {packet.destination_port} ({service_name})."
                )

        return None

    def reset(self):
        """Resets detector memory state."""
        self.port_history.clear()
        self.alert_cooldowns.clear()
        self.syn_history.clear()
