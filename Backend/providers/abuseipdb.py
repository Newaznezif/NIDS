"""AbuseIPDB adapter (IP reputation / abuse reports)."""
import urllib.error
import urllib.parse

from .base import ThreatIntelProvider, ProviderResult, STATUS_OK, STATUS_NO_RESULT, http_get_json

BASE = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "AbuseIPDB"
    supports = {"ip"}

    def _headers(self):
        return {"Key": self.api_key, "Accept": "application/json"}

    def lookup_ip(self, ip):
        if not self.configured:
            return self._not_configured("ip", ip)
        url = f"{BASE}?{urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''})}"
        try:
            payload = http_get_json(url, self._headers())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ProviderResult.make(self.name, "ip", ip, STATUS_NO_RESULT,
                                           reason="No AbuseIPDB record for this IP.")
            return self._unavailable("ip", ip, e)
        except Exception as e:
            return self._unavailable("ip", ip, e)
        data = (payload or {}).get("data") or {}
        if not data:
            return ProviderResult.make(self.name, "ip", ip, STATUS_NO_RESULT,
                                       reason="Provider returned no data.")
        out = {
            "abuse_confidence_percentage": data.get("abuseConfidencePercentage"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "is_proxy": data.get("isProxy"),
            "is_vpn": data.get("isVpn"),
            "last_reported_at": data.get("lastReportedAt"),
        }
        return ProviderResult.make(self.name, "ip", ip, STATUS_OK,
                                   data={k: v for k, v in out.items() if v is not None})
