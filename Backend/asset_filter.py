"""Asset IP filtering.

Decides whether a captured packet is relevant to the monitored asset. This runs
BEFORE any asset-specific detection so unrelated traffic never enters the
asset detection pipeline.
"""
import ipaddress
import logging
from typing import Optional

from .models import Packet

logger = logging.getLogger("NIDS.AssetFilter")

VALID_MODES = ("BOTH", "INBOUND", "OUTBOUND")


class AssetFilter:
    """Filters packets by their relationship to a monitored IPv4 asset."""

    def __init__(self, asset_ip: str = "", mode: str = "BOTH"):
        mode = (mode or "BOTH").upper()
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid asset mode '{mode}'. Must be one of {VALID_MODES}.")
        self.mode = mode
        self.asset_ip = ""
        if asset_ip:
            # Validate strictly as IPv4; raises ValueError on bad input.
            self.asset_ip = str(ipaddress.IPv4Address(asset_ip.strip()))

    @property
    def enabled(self) -> bool:
        return bool(self.asset_ip)

    def matches(self, packet: Packet) -> bool:
        """True if the packet is relevant to the monitored asset under the current mode."""
        if not self.enabled:
            # No asset configured: all traffic is in scope (legacy global monitoring).
            return True
        if self.mode == "INBOUND":
            return packet.destination_ip == self.asset_ip
        if self.mode == "OUTBOUND":
            return packet.source_ip == self.asset_ip
        # BOTH
        return packet.source_ip == self.asset_ip or packet.destination_ip == self.asset_ip

    def direction(self, packet: Packet) -> Optional[str]:
        """Describes the packet's relationship to the asset, or None if unrelated."""
        if not self.enabled:
            return None
        is_src = packet.source_ip == self.asset_ip
        is_dst = packet.destination_ip == self.asset_ip
        if is_src and is_dst:
            return "LOCAL"
        if is_dst:
            return "INBOUND"
        if is_src:
            return "OUTBOUND"
        return None

    def describe(self) -> dict:
        return {"asset_ip": self.asset_ip, "mode": self.mode, "enabled": self.enabled}
