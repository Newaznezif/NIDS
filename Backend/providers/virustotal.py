"""VirusTotal v3 adapter (IP / domain / URL / file)."""
import base64
import urllib.error

from .base import ThreatIntelProvider, ProviderResult, STATUS_OK, STATUS_NO_RESULT, http_get_json

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(ThreatIntelProvider):
    name = "VirusTotal"
    supports = {"ip", "domain", "url", "hash"}

    def __init__(self, api_key=""):
        super().__init__(api_key)

    def _headers(self):
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def _get(self, path, itype, indicator):
        if not self.configured:
            return self._not_configured(itype, indicator)
        try:
            payload = http_get_json(f"{BASE}{path}", self._headers())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ProviderResult.make(self.name, itype, indicator, STATUS_NO_RESULT,
                                           reason="Provider has no record for this indicator.")
            return self._unavailable(itype, indicator, e)
        except Exception as e:
            return self._unavailable(itype, indicator, e)
        attrs = (payload or {}).get("data", {}).get("attributes", {})
        if not attrs:
            return ProviderResult.make(self.name, itype, indicator, STATUS_NO_RESULT,
                                       reason="Provider returned no attributes.")
        return ProviderResult.make(self.name, itype, indicator, STATUS_OK, data=self._normalize(attrs))

    @staticmethod
    def _normalize(a: dict) -> dict:
        stats = a.get("last_analysis_stats", {}) or {}
        out = {
            "reputation": a.get("reputation"),
            "malicious_detections": stats.get("malicious"),
            "suspicious_detections": stats.get("suspicious"),
            "harmless_detections": stats.get("harmless"),
            "undetected_detections": stats.get("undetected"),
            "total_engines": sum(v for v in stats.values() if isinstance(v, int)) or None,
            "tags": a.get("tags", []),
            "categories": a.get("categories", []),
            "country": a.get("country"),
            "asn": a.get("asn"),
            "network": a.get("network"),
            "owner": a.get("whois", "")[:200] or None,
            "file_type": a.get("type_description") or a.get("magic"),
            "file_size": a.get("size"),
            "names": (a.get("names") or [])[:10],
            "meaningful_name": a.get("meaningful_name"),
            "first_seen": a.get("first_submission_date"),
            "last_seen": a.get("last_submission_date") or a.get("last_analysis_date"),
            "signatures": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            "behaviour": (a.get("behaviours") or [{}])[0].get("name") if a.get("behaviours") else None,
        }
        return {k: v for k, v in out.items() if v not in (None, "", [], {})}

    def lookup_ip(self, ip):
        return self._get(f"/ip_addresses/{ip}", "ip", ip)

    def lookup_domain(self, domain):
        return self._get(f"/domains/{domain}", "domain", domain)

    def lookup_url(self, url):
        ident = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._get(f"/urls/{ident}", "url", url)

    def lookup_hash(self, digest):
        return self._get(f"/files/{digest}", "hash", digest)
