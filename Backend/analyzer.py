import time
import logging
from typing import Optional, Dict, Any
from .models import Packet

logger = logging.getLogger("NIDS.Analyzer")

try:
    from scapy.all import IP, TCP, UDP, ICMP, ARP # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy library not available or failed to import.")

class PacketAnalyzer:
    """Extracts structured metadata from raw Scapy packets or dict objects."""

    @staticmethod
    def parse_scapy_packet(scapy_pkt) -> Optional[Packet]:
        """Parses a Scapy packet into a standardized Packet dataclass."""
        try:
            if not SCAPY_AVAILABLE:
                return None

            source_ip = "0.0.0.0"
            destination_ip = "0.0.0.0"
            source_port = 0
            destination_port = 0
            protocol = "OTHER"
            length = len(scapy_pkt)
            flags = ""

            # Check IP Layer
            if scapy_pkt.haslayer(IP):
                ip_layer = scapy_pkt[IP]
                source_ip = ip_layer.src
                destination_ip = ip_layer.dst
                protocol = "IP"

                # Check TCP Layer
                if scapy_pkt.haslayer(TCP):
                    tcp_layer = scapy_pkt[TCP]
                    source_port = int(tcp_layer.sport)
                    destination_port = int(tcp_layer.dport)
                    protocol = "TCP"
                    flags = str(tcp_layer.flags)

                # Check UDP Layer
                elif scapy_pkt.haslayer(UDP):
                    udp_layer = scapy_pkt[UDP]
                    source_port = int(udp_layer.sport)
                    destination_port = int(udp_layer.dport)
                    protocol = "UDP"

                # Check ICMP Layer
                elif scapy_pkt.haslayer(ICMP):
                    protocol = "ICMP"

            elif scapy_pkt.haslayer(ARP):
                arp_layer = scapy_pkt[ARP]
                source_ip = arp_layer.psrc
                destination_ip = arp_layer.pdst
                protocol = "ARP"

            else:
                return None # Skip non-IP traffic for intrusion analysis

            return Packet(
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                timestamp=time.time(),
                length=length,
                flags=flags
            )

        except Exception as e:
            logger.debug(f"Failed to parse packet: {e}")
            return None

    @staticmethod
    def parse_dict_packet(data: Dict[str, Any]) -> Packet:
        """Parses a dictionary representation into a Packet object."""
        return Packet(
            source_ip=data.get("source_ip", "192.168.1.100"),
            destination_ip=data.get("destination_ip", "192.168.1.10"),
            source_port=data.get("source_port", 49152),
            destination_port=data.get("destination_port", 80),
            protocol=data.get("protocol", "TCP"),
            timestamp=data.get("timestamp", time.time()),
            length=data.get("length", 64),
            flags=data.get("flags", "S")
        )
