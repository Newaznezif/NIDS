from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any

@dataclass
class Packet:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str = "TCP"
    timestamp: float = field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    length: int = 64
    flags: str = ""
    interface: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["iso_timestamp"] = datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()
        return d

@dataclass
class Alert:
    attack_type: str
    severity: str
    confidence: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    details: str
    id: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "ACTIVE"
    # The monitored asset this alert relates to ("" when monitoring all traffic).
    asset_ip: str = ""
    # Observed evidence backing this detection (counts, ports, window, rate). Never fabricated.
    evidence: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
