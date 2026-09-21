"""GreyNoise adapter (IP noise / riot context)."""
import urllib.error

from .base import ThreatIntelProvider, ProviderResult, STATUS_OK, STATUS_NO_RESULT, http_get_json

BASE = "https://api.greynoise.io/v2/noise/context"


class GreyNoiseProvider(ThreatIntelProvider):
    name = "GreyNoise"
    supports = {"ip"}

    def _headers(self):
        return {"Key": self.api_key, "Accept": "application/json"}

    def lookup_ip(self, ip):
        if not self.configured:
            return self._not_configured("ip", ip)
        try:
            payload = http_get_json(f"{BASE}/{ip}", self._headers())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ProviderResult.make(self.name, "ip", ip, STATUS_NO_RESULT,
                                           reason="GreyNoise has no context for this IP.")
            return self._unavailable("ip", ip, e)
        except Exception as e:
            return self._unavailable("ip", ip, e)
        if not payload:
            return ProviderResult.make(self.name, "ip", ip, STATUS_NO_RESULT,
                                       reason="Provider returned an empty record.")
        out = {
            "classification": payload.get("classification"),
            "noise": payload.get("noise"),
            "riot": payload.get("riot"),
            "actor": payload.get("actor"),
            "tags": payload.get("tags", []),
            "country_name": payload.get("country_name"),
            "organization": payload.get("organization"),
            "operating_system": payload.get("operating_system"),
            "category": payload.get("category"),
            "first_seen": payload.get("first_seen"),
            "last_seen": payload.get("last_seen"),
        }
        return ProviderResult.make(self.name, "ip", ip, STATUS_OK,
                                   data={k: v for k, v in out.items() if v not in (None, "", [])})
