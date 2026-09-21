"""AlienVault OTX adapter (IP / domain / URL / file pulses)."""
import urllib.error
import urllib.parse

from .base import ThreatIntelProvider, ProviderResult, STATUS_OK, STATUS_NO_RESULT, http_get_json

BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTXProvider(ThreatIntelProvider):
    name = "AlienVault OTX"
    supports = {"ip", "domain", "url", "hash"}

    def _headers(self):
        return {"X-OTX-API-KEY": self.api_key}

    def _general(self, kind, value, itype):
        if not self.configured:
            return self._not_configured(itype, value)
        quoted = urllib.parse.quote(value, safe="")
        url = f"{BASE}/{kind}/{quoted}/general"
        try:
            payload = http_get_json(url, self._headers())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ProviderResult.make(self.name, itype, value, STATUS_NO_RESULT,
                                           reason="No OTX record for this indicator.")
            return self._unavailable(itype, value, e)
        except Exception as e:
            return self._unavailable(itype, value, e)
        if not payload:
            return ProviderResult.make(self.name, itype, value, STATUS_NO_RESULT,
                                       reason="Provider returned an empty record.")
        out = {
            "reputation": payload.get("reputation"),
            "pulse_count": payload.get("pulse_count"),
            "country_name": payload.get("country_name"),
            "type_title": payload.get("type_title"),
            "validation": payload.get("validation"),
            "sections": payload.get("sections", []),
            "tags": (payload.get("pulse_info") or {}).get("tags", []) if isinstance(payload.get("pulse_info"), dict) else [],
            "whois": (payload.get("whois") or "")[:200] or None,
        }
        return ProviderResult.make(self.name, itype, value, STATUS_OK,
                                   data={k: v for k, v in out.items() if v not in (None, "", [])})

    def lookup_ip(self, ip):
        return self._general("IPv4", ip, "ip")

    def lookup_domain(self, domain):
        return self._general("domain", domain, "domain")

    def lookup_url(self, url):
        return self._general("url", url, "url")

    def lookup_hash(self, digest):
        return self._general("file", digest, "hash")
