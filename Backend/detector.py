import time
import logging
import threading
from collections import defaultdict
from typing import Optional, List, Dict, Set
from .models import Packet, Alert
from .config import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
    SYN_FLOOD_THRESHOLD,
    SYN_FLOOD_WINDOW,
    SYN_FLOOD_RATE_THRESHOLD,
    ALERT_COOLDOWN,
    SUSPICIOUS_PORTS,
)

logger = logging.getLogger("NIDS.Detector")


class IntrusionDetector:
    """Stateful rule-based intrusion detection engine.

    All detection state is guarded by a lock so the capture thread and any
    request thread (demo triggers, /api/clear) can operate safely together.
    """

    def __init__(
        self,
        port_scan_threshold: int = PORT_SCAN_THRESHOLD,
        port_scan_window: float = PORT_SCAN_WINDOW,
        syn_flood_threshold: int = SYN_FLOOD_THRESHOLD,
        syn_flood_window: float = SYN_FLOOD_WINDOW,
        cooldown_period: float = ALERT_COOLDOWN,
        suspicious_ports: Optional[Dict[int, dict]] = None,
        syn_flood_rate_threshold: float = SYN_FLOOD_RATE_THRESHOLD,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window = syn_flood_window
        self.syn_flood_rate_threshold = syn_flood_rate_threshold
        self.cooldown_period = cooldown_period
        self.suspicious_ports = suspicious_ports if suspicious_ports is not None else SUSPICIOUS_PORTS

        self._lock = threading.RLock()

        # Port Scan state: (src_ip, dst_ip) -> list of (dst_port, timestamp)
        self.port_history: Dict[tuple, List[tuple]] = defaultdict(list)
        # SYN Flood state: src_ip -> list of timestamps
        self.syn_history: Dict[str, List[float]] = defaultdict(list)
        # Cooldowns: (src_ip, dst_ip, attack_type) -> last_alert_timestamp
        self.alert_cooldowns: Dict[tuple, float] = {}

        self._last_prune = 0.0
        self._prune_interval = 5.0  # seconds between stale-key sweeps

    # --- public API ---

    def analyze_packet(self, packet: Packet, asset_ip: str = "") -> Optional[Alert]:
        """Analyze one packet against all rules. Returns an Alert or None.

        asset_ip, when provided, is stamped onto any generated alert to record which
        monitored asset the detection relates to. Never raises: a malformed packet is
        treated as non-matching.
        """
        try:
            current_time = float(packet.timestamp)
        except (TypeError, ValueError):
            current_time = time.time()

        with self._lock:
            self._maybe_prune(current_time)

            for rule in (self._check_port_scan, self._check_syn_flood, self._check_suspicious_port):
                alert = rule(packet, current_time)
                if alert:
                    alert.asset_ip = asset_ip
                    return alert
            return None

    def reset(self):
        """Clears all detector memory state."""
        with self._lock:
            self.port_history.clear()
            self.syn_history.clear()
            self.alert_cooldowns.clear()
            self._last_prune = 0.0

    # --- rules ---

    def _check_port_scan(self, packet: Packet, current_time: float) -> Optional[Alert]:
        """Flags a host contacting many unique destination ports on one target in a window."""
        if not packet.destination_port:
            return None

        key = (packet.source_ip, packet.destination_ip)
        self.port_history[key].append((packet.destination_port, current_time))

        cutoff = current_time - self.port_scan_window
        self.port_history[key] = [(p, ts) for p, ts in self.port_history[key] if ts >= cutoff]

        unique_ports: Set[int] = {p for p, _ in self.port_history[key]}
        if len(unique_ports) < self.port_scan_threshold:
            return None

        if not self._cooldown_ok(key + ("PORT_SCAN",), current_time):
            return None

        # PORT_SCAN is a reconnaissance attempt: consistently HIGH severity. The alert
        # fires the moment the unique-port threshold is crossed, so severity is derived
        # from the attack class rather than a post-hoc breadth that cooldown would mask.
        severity = "HIGH"

        details = (
            f"{len(unique_ports)} unique destination ports probed from "
            f"{packet.source_ip} to {packet.destination_ip} within {self.port_scan_window}s window. "
            f"Sample ports: {sorted(unique_ports)[:10]}"
        )
        logger.warning(f"[DETECTION] PORT_SCAN from {packet.source_ip}: {len(unique_ports)} ports")

        window_events = self.port_history[key]
        return Alert(
            attack_type="PORT_SCAN",
            severity=severity,
            confidence=0.92,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
            details=details,
            evidence={
                "unique_ports": len(unique_ports),
                "ports": sorted(unique_ports),
                "packet_count": len(window_events),
                "window_seconds": self.port_scan_window,
                "threshold": self.port_scan_threshold,
            },
            first_seen=min(ts for _, ts in window_events),
            last_seen=max(ts for _, ts in window_events),
        )

    def _check_syn_flood(self, packet: Packet, current_time: float) -> Optional[Alert]:
        """Flags a source sending many genuine connection-open (SYN, not SYN-ACK) packets."""
        if packet.protocol != "TCP":
            return None
        flags = packet.flags or ""
        # A real SYN opens a connection: SYN set, ACK not set. SYN-ACK ("SA") is a
        # server reply and must NOT be counted, otherwise normal traffic looks like a flood.
        if "S" not in flags or "A" in flags:
            return None

        src_ip = packet.source_ip
        self.syn_history[src_ip].append(current_time)

        cutoff = current_time - self.syn_flood_window
        self.syn_history[src_ip] = [ts for ts in self.syn_history[src_ip] if ts >= cutoff]

        syn_count = len(self.syn_history[src_ip])
        if syn_count < self.syn_flood_threshold:
            return None

        # Observed rate over the window; optionally require a minimum rate so a slow,
        # spread-out burst is not misclassified as a flood.
        observed_rate = round(syn_count / self.syn_flood_window, 2)
        if self.syn_flood_rate_threshold and observed_rate < self.syn_flood_rate_threshold:
            return None

        if not self._cooldown_ok((src_ip, packet.destination_ip, "SYN_FLOOD"), current_time):
            return None

        syn_events = self.syn_history[src_ip]
        return Alert(
            attack_type="SYN_FLOOD",
            severity="CRITICAL",
            confidence=0.95,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            protocol="TCP",
            details=(
                f"Sustained SYN flood: {syn_count} connection-open packets from "
                f"{src_ip} within {self.syn_flood_window}s (threshold {self.syn_flood_threshold}, "
                f"rate {observed_rate}/s)."
            ),
            evidence={
                "syn_count": syn_count,
                "packet_count": syn_count,
                "window_seconds": self.syn_flood_window,
                "observed_rate_per_sec": observed_rate,
                "threshold": self.syn_flood_threshold,
                "rate_threshold": self.syn_flood_rate_threshold,
            },
            first_seen=min(syn_events),
            last_seen=max(syn_events),
        )

    def _check_suspicious_port(self, packet: Packet, current_time: float) -> Optional[Alert]:
        """Flags a connection attempt to an explicitly configured high-risk port."""
        port = packet.destination_port
        rule = self.suspicious_ports.get(port)
        if not rule:
            return None

        cooldown_key = (packet.source_ip, packet.destination_ip, f"SUSPICIOUS_PORT_{port}")
        if not self._cooldown_ok(cooldown_key, current_time):
            return None

        return Alert(
            attack_type="SUSPICIOUS_PORT",
            severity=rule["severity"],
            confidence=0.85,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=port,
            protocol=packet.protocol,
            details=f"Connection attempt to high-risk port {port} ({rule['label']}) over {packet.protocol}.",
            evidence={
                "reason": rule["label"],
                "port": port,
                "protocol": packet.protocol,
                "rule": "SUSPICIOUS_PORT",
            },
            first_seen=current_time,
            last_seen=current_time,
        )

    # --- helpers ---

    def _cooldown_ok(self, cooldown_key: tuple, current_time: float) -> bool:
        """Returns True and records the time if this key is allowed to alert now."""
        last = self.alert_cooldowns.get(cooldown_key, 0.0)
        if current_time - last < self.cooldown_period:
            return False
        self.alert_cooldowns[cooldown_key] = current_time
        return True

    def _maybe_prune(self, current_time: float) -> None:
        """Periodically drop stale tracking keys so memory stays bounded during
        continuous monitoring. Runs at most once per prune interval."""
        if current_time - self._last_prune < self._prune_interval:
            return
        self._last_prune = current_time

        port_cutoff = current_time - self.port_scan_window
        for key in [k for k, v in self.port_history.items() if not v or v[-1][1] < port_cutoff]:
            del self.port_history[key]

        syn_cutoff = current_time - self.syn_flood_window
        for key in [k for k, v in self.syn_history.items() if not v or v[-1] < syn_cutoff]:
            del self.syn_history[key]

        cooldown_cutoff = current_time - self.cooldown_period
        for key in [k for k, ts in self.alert_cooldowns.items() if ts < cooldown_cutoff]:
            del self.alert_cooldowns[key]
