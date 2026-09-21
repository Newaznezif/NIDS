import threading
import time
import logging
import random
import errno
from typing import Dict, Any, Optional

from .config import (
    DEFAULT_INTERFACE,
    PACKET_FLUSH_COUNT,
    PACKET_FLUSH_INTERVAL,
    ASSET_IP,
    ASSET_MODE,
    CAPTURE_LIVENESS_SECONDS,
    FLOW_WINDOW,
)
from .analyzer import PacketAnalyzer, SCAPY_AVAILABLE
from .asset_filter import AssetFilter
from .detector import IntrusionDetector
from .alert_engine import process_alert
from .database import save_packet, increment_packet_count

logger = logging.getLogger("NIDS.Sniffer")

try:
    from scapy.all import sniff, conf, get_if_list  # type: ignore
except Exception:
    sniff = None
    conf = None
    get_if_list = None

# Capture states. LIVE is only reported while the capture thread is running AND has
# actually received a packet within CAPTURE_LIVENESS_SECONDS.
STATE_INITIALIZING = "INITIALIZING"
STATE_LIVE = "LIVE"
STATE_NO_TRAFFIC = "NO_TRAFFIC"
STATE_CAPTURE_ERROR = "CAPTURE_ERROR"
STATE_PERMISSION_DENIED = "PERMISSION_DENIED"
STATE_NO_INTERFACE = "NO_INTERFACE"
STATE_STOPPED = "STOPPED"
STATE_DISCONNECTED = "DISCONNECTED"


class NetworkSniffer:
    """
    Manages live packet sniffing via Scapy in a background thread.

    Responsibilities in the pipeline:
      Packet Capture -> Packet Parsing (analyzer) -> Asset Filtering ->
      Flow aggregation -> Detection (detector) -> Alert creation (alert_engine).

    The capture state machine reports honest status: LIVE only while packets are
    actually arriving; otherwise NO_TRAFFIC / CAPTURE_ERROR / PERMISSION_DENIED /
    NO_INTERFACE / STOPPED / DISCONNECTED.
    """

    def __init__(self, detector: IntrusionDetector):
        self.detector = detector
        self.is_running = False
        self.interface = DEFAULT_INTERFACE
        self.resolved_interface: Optional[str] = None
        self.thread: Optional[threading.Thread] = None
        self.error_message = None

        # Capture state machine
        self._capture_state = STATE_INITIALIZING
        self._capture_verified = False
        self._thread_died = False
        self._last_packet_time: Optional[float] = None

        # Asset monitoring
        self.asset_filter = AssetFilter(ASSET_IP, ASSET_MODE)

        # Counters are mutated from the capture thread; guard them for safe reads.
        # RLock because status helpers nest (get_status_info -> current_capture_state).
        self._lock = threading.RLock()
        self.packets_count = 0
        self.bytes_count = 0
        self.asset_packets_count = 0
        self.asset_bytes_count = 0

        # Flow aggregation: 5-tuple -> last_seen timestamp
        self._flows: Dict[tuple, float] = {}
        self.flows_total = 0  # cumulative distinct flows observed (monitored scope)

        # Batched DB flush state (avoids one SQLite commit per captured packet).
        self._pending_packets = 0
        self._pending_bytes = 0
        self._last_flush = time.time()

    # --- lifecycle ---

    def start(self):
        """Attempts to start live sniffing; reports an honest state on failure."""
        self.is_running = True
        self._thread_died = False

        if not SCAPY_AVAILABLE or sniff is None:
            self._capture_state = STATE_NO_INTERFACE
            self.error_message = "Scapy or WinPcap/Npcap missing. No packet-capture capability."
            logger.warning(f"[SNIFFER] {self.error_message}")
            return

        self._resolve_interface()
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        logger.info("[SNIFFER] Background sniffing thread launched.")

    def stop(self):
        """Stops the sniffer background loop and flushes pending counters."""
        self.is_running = False
        self._capture_state = STATE_STOPPED
        self._flush_packet_counters(force=True)

    def _resolve_interface(self):
        """Determine the actual capture interface name to report and use."""
        if self.interface:
            self.resolved_interface = self.interface
            return
        try:
            if conf is not None and getattr(conf, "iface", None) is not None:
                name = getattr(conf.iface, "name", None) or str(conf.iface)
                if name and name != "None":
                    self.resolved_interface = name
                    return
            if get_if_list is not None:
                ifaces = get_if_list()
                if ifaces:
                    self.resolved_interface = str(ifaces[0])
                    return
        except Exception as e:
            logger.warning(f"[SNIFFER] Could not resolve interface: {e}")
        self.resolved_interface = None

    # --- capture state ---

    def current_capture_state(self) -> str:
        """Compute the honest capture state right now."""
        with self._lock:
            if self._capture_state in (STATE_STOPPED,):
                return STATE_STOPPED
            if self._capture_state in (
                STATE_CAPTURE_ERROR, STATE_PERMISSION_DENIED, STATE_NO_INTERFACE
            ):
                return self._capture_state
            if not self.is_running:
                return STATE_STOPPED
            if self._thread_died:
                return STATE_DISCONNECTED
            if not self._capture_verified:
                return STATE_INITIALIZING
            if self._last_packet_time is None:
                return STATE_NO_TRAFFIC
            if (time.time() - self._last_packet_time) <= CAPTURE_LIVENESS_SECONDS:
                return STATE_LIVE
            return STATE_NO_TRAFFIC

    def _classify_capture_error(self, exc: Exception) -> str:
        """Map a capture exception to an honest failure state."""
        if isinstance(exc, PermissionError):
            return STATE_PERMISSION_DENIED
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in (errno.EPERM, errno.EACCES):
            return STATE_PERMISSION_DENIED
        msg = str(exc).lower()
        if "permission" in msg or "denied" in msg or "administrator" in msg or "access is denied" in msg:
            return STATE_PERMISSION_DENIED
        if "no such device" in msg or "interface" in msg or "not found" in msg or "npcap" in msg or "winpcap" in msg:
            return STATE_NO_INTERFACE
        return STATE_CAPTURE_ERROR

    # --- capture loop ---

    def _sniff_loop(self):
        """Background worker thread for Scapy sniff()."""
        try:
            logger.info("Initializing network interface packet capture...")
            # Probe capture capability before claiming LIVE. On Windows without
            # Npcap/admin this raises and we report the specific failure state.
            sniff(iface=self.interface, count=1, store=False, timeout=2)
            self._capture_verified = True
            logger.info(f"[SNIFFER] Live capture verified on interface {self.resolved_interface}.")

            while self.is_running:
                sniff(
                    iface=self.interface,
                    prn=self._handle_scapy_packet,
                    store=False,
                    count=10,
                    timeout=1,
                )
                self._flush_packet_counters(force=False)
        except Exception as e:
            state = self._classify_capture_error(e)
            self._capture_state = state
            self._capture_verified = False
            self.error_message = f"Capture failed ({type(e).__name__}: {e}). State={state}."
            logger.warning(f"[SNIFFER] {self.error_message}")
        finally:
            self._flush_packet_counters(force=True)
            # If the thread exits while still supposed to be running, it died unexpectedly.
            if self.is_running and self._capture_verified:
                self._thread_died = True

    def _handle_scapy_packet(self, scapy_pkt):
        """Processes each captured raw packet. Never raises into the capture loop."""
        if not self.is_running:
            return
        try:
            packet = PacketAnalyzer.parse_scapy_packet(scapy_pkt)
            if not packet:
                return

            now = time.time()
            with self._lock:
                self.packets_count += 1
                self.bytes_count += packet.length
                self._pending_packets += 1
                self._pending_bytes += packet.length
                self._last_packet_time = now

            self._flush_packet_counters(force=False)

            # ASSET FILTER: only asset-relevant packets enter the detection pipeline.
            if self.asset_filter.enabled and not self.asset_filter.matches(packet):
                return

            with self._lock:
                self.asset_packets_count += 1
                self.asset_bytes_count += packet.length
                self._track_flow(packet, now)

            alert = self.detector.analyze_packet(packet, asset_ip=self.asset_filter.asset_ip)
            if alert:
                process_alert(alert)
        except Exception as e:
            # One malformed packet must not break continuous capture.
            logger.debug(f"[SNIFFER] Skipped packet due to error: {e}")

    def _track_flow(self, packet, now: float):
        """Aggregate distinct 5-tuple flows (monitored scope) with bounded memory."""
        key = (packet.source_ip, packet.destination_ip, packet.source_port,
               packet.destination_port, packet.protocol)
        if key not in self._flows:
            self.flows_total += 1
        self._flows[key] = now
        # Prune stale flows periodically to bound memory.
        if len(self._flows) > 5000:
            cutoff = now - FLOW_WINDOW
            for k in [k for k, ts in self._flows.items() if ts < cutoff]:
                del self._flows[k]

    def active_flows(self) -> int:
        """Number of distinct flows seen within FLOW_WINDOW."""
        now = time.time()
        cutoff = now - FLOW_WINDOW
        with self._lock:
            return sum(1 for ts in self._flows.values() if ts >= cutoff)

    def _flush_packet_counters(self, force: bool = False):
        """Writes accumulated packet counters to SQLite in batches."""
        with self._lock:
            now = time.time()
            due = force or (
                self._pending_packets >= PACKET_FLUSH_COUNT
                or (now - self._last_flush) >= PACKET_FLUSH_INTERVAL
            )
            if not due or self._pending_packets == 0:
                self._last_flush = now if force else self._last_flush
                return
            packets, bytes_ = self._pending_packets, self._pending_bytes
            self._pending_packets = 0
            self._pending_bytes = 0
            self._last_flush = now

        try:
            increment_packet_count(count=packets, total_bytes=bytes_)
        except Exception as e:
            logger.error(f"[SNIFFER] Failed to flush packet counters: {e}")

    # --- asset monitoring control ---

    def start_monitoring(self, asset_ip: str, mode: str = "BOTH") -> Dict[str, Any]:
        """Begin asset-scoped monitoring. Raises ValueError on a bad asset IP/mode."""
        new_filter = AssetFilter(asset_ip, mode)  # validates
        with self._lock:
            self.asset_filter = new_filter
            self.asset_packets_count = 0
            self.asset_bytes_count = 0
            self._flows.clear()
            self.flows_total = 0
        self.detector.reset()
        logger.info(f"[MONITOR] Started monitoring asset {new_filter.asset_ip} mode={new_filter.mode}")
        return self.get_monitor_status()

    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop asset-scoped monitoring (capture keeps running globally)."""
        with self._lock:
            self.asset_filter = AssetFilter("", "BOTH")
        logger.info("[MONITOR] Stopped asset monitoring.")
        return self.get_monitor_status()

    def get_monitor_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "asset": self.asset_filter.describe(),
                "capture_state": self.current_capture_state(),
                "interface": self.resolved_interface or "Auto/Default",
                "packets_observed": self.packets_count,
                "asset_packets_observed": self.asset_packets_count,
                "flows_total": self.flows_total,
                "flows_active": self.active_flows(),
                "last_packet_time": self._last_packet_time,
                "liveness_seconds": CAPTURE_LIVENESS_SECONDS,
                "error_message": self.error_message,
            }

    # --- legacy demo simulation (explicitly NOT real capture; never affects liveness) ---

    def trigger_demo_port_scan(self, source_ip: str = "192.168.1.100", target_ip: str = "192.168.1.10", ports_count: int = 10) -> Dict[str, Any]:
        """
        Simulates controlled network traffic representing a Port Scan.
        Pushes packets sequentially through Analyzer -> Detector -> Alert Engine -> Database.
        Marked as simulation; does not update capture liveness.
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
                "timestamp": now + (i * 0.1),
                "length": random.randint(54, 128),
                "flags": "S",
            }
            packet = PacketAnalyzer.parse_dict_packet(pkt_dict)
            with self._lock:
                self.packets_count += 1
                self.bytes_count += packet.length
            save_packet(pkt_dict)

            alert = self.detector.analyze_packet(packet)
            if alert:
                generated_alerts.append(process_alert(alert))

        return {
            "status": "success",
            "simulated": True,
            "packets_generated": len(target_ports),
            "alerts_triggered": len(generated_alerts),
            "alerts": generated_alerts,
        }

    def trigger_demo_syn_flood(self, source_ip: str = "10.0.0.88", target_ip: str = "192.168.1.10", count: int = 35) -> Dict[str, Any]:
        """Simulates a SYN Flood attack vector. Marked as simulation."""
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
                "flags": "S",
            }
            packet = PacketAnalyzer.parse_dict_packet(pkt_dict)
            with self._lock:
                self.packets_count += 1
                self.bytes_count += packet.length
            save_packet(pkt_dict)

            alert = self.detector.analyze_packet(packet)
            if alert:
                generated_alerts.append(process_alert(alert))

        return {
            "status": "success",
            "simulated": True,
            "packets_generated": count,
            "alerts_triggered": len(generated_alerts),
            "alerts": generated_alerts,
        }

    def get_status_info(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "mode": self.current_capture_state(),
                "capture_state": self.current_capture_state(),
                "is_running": self.is_running,
                "interface": self.resolved_interface or "Auto/Default",
                "packets_captured": self.packets_count,
                "bytes_captured": self.bytes_count,
                "asset_packets_captured": self.asset_packets_count,
                "flows_total": self.flows_total,
                "flows_active": self.active_flows(),
                "asset": self.asset_filter.describe(),
                "last_packet_time": self._last_packet_time,
                "error_message": self.error_message,
            }
