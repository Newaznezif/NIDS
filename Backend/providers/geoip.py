"""Key-free geolocation adapter (ipwho.is). Disabled via GEOIP_ENABLED=False."""
import urllib.error

from ..config import GEOIP_ENABLED
from .base import ThreatIntelProvider, ProviderResult, STATUS_OK, STATUS_NO_RESULT, STATUS_NOT_CONFIGURED, http_get_json

BASE = "https://ipwho.is"


class GeoIPProvider(ThreatIntelProvider):
    name = "GeoIP (ipwho.is)"
    supports = {"ip"}

    def __init__(self, api_key=""):
        super().__init__(api_key)
        self.enabled = GEOIP_ENABLED

    @property
    def configured(self):
        return self.enabled

    def status(self):
        s = super().status()
        if not self.enabled:
            s["status"] = "NOT CONFIGURED"
        return s

    def lookup_ip(self, ip):
        if not self.enabled:
            return ProviderResult.make(self.name, "ip", ip, STATUS_NOT_CONFIGURED,
                                       reason="Geolocation provider disabled by configuration.")
        try:
            payload = http_get_json(f"{BASE}/{ip}")
        except urllib.error.HTTPError as e:
            return self._unavailable("ip", ip, e)
        except Exception as e:
            return self._unavailable("ip", ip, e)
        if not payload or payload.get("success") is False:
            return ProviderResult.make(self.name, "ip", ip, STATUS_NO_RESULT,
                                       reason=(payload or {}).get("message", "No geolocation record."))
        conn = payload.get("connection", {}) or {}
        out = {
            "country": payload.get("country"),
            "country_code": payload.get("country_code"),
            "region": payload.get("region"),
            "city": payload.get("city"),
            "latitude": payload.get("latitude"),
            "longitude": payload.get("longitude"),
            "isp": conn.get("isp"),
            "organization": conn.get("org"),
            "asn": conn.get("asn"),
        }
        return ProviderResult.make(self.name, "ip", ip, STATUS_OK,
                                   data={k: v for k, v in out.items() if v not in (None, "")})
