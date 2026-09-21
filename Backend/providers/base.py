"""Base class and HTTP helper for threat-intelligence provider adapters.

Providers never fabricate data. Every lookup returns an explicit status:
  OK                     - the provider returned a usable payload
  NOT_CONFIGURED         - no API key / provider disabled
  TEMPORARILY_UNAVAILABLE- network/HTTP failure or provider error
  NO_RESULT              - provider responded but had no record for the IOC
  UNSUPPORTED            - provider does not handle this indicator type
All successful payloads carry provenance EXTERNAL INTELLIGENCE plus the
provider name and retrieval timestamp.
"""
import json
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

from ..config import PROVIDER_TIMEOUT

STATUS_OK = "OK"
STATUS_NOT_CONFIGURED = "NOT CONFIGURED"
STATUS_UNAVAILABLE = "TEMPORARILY UNAVAILABLE"
STATUS_NO_RESULT = "NO RESULT"
STATUS_UNSUPPORTED = "UNSUPPORTED INDICATOR TYPE"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def http_get_json(url: str, headers: dict = None, timeout: float = PROVIDER_TIMEOUT):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


class ProviderResult(dict):
    """Convenience dict with the canonical result shape."""

    @staticmethod
    def make(provider, indicator_type, indicator, status, data=None, reason=""):
        return {
            "provider": provider,
            "indicator_type": indicator_type,
            "indicator": indicator,
            "status": status,
            "reason": reason,
            "retrieved_at": _now(),
            "provenance": "EXTERNAL INTELLIGENCE" if status == STATUS_OK else "UNAVAILABLE",
            "data": data or {},
        }


class ThreatIntelProvider:
    name = "base"
    supports = {"ip", "domain", "url", "hash"}

    def __init__(self, api_key: str = ""):
        self.api_key = api_key or ""

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def status(self) -> dict:
        return {
            "provider": self.name,
            "configured": self.configured,
            "status": "CONFIGURED" if self.configured else "NOT CONFIGURED",
            "supports": sorted(self.supports),
        }

    def _not_configured(self, itype, indicator):
        return ProviderResult.make(self.name, itype, indicator, STATUS_NOT_CONFIGURED,
                                   reason="API key not configured for this provider.")

    def _unavailable(self, itype, indicator, exc):
        reason = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, urllib.error.HTTPError):
            reason = f"HTTP {exc.code} from provider"
        return ProviderResult.make(self.name, itype, indicator, STATUS_UNAVAILABLE, reason=reason)

    def _unsupported(self, itype, indicator):
        return ProviderResult.make(self.name, itype, indicator, STATUS_UNSUPPORTED,
                                   reason=f"{self.name} does not provide {itype} lookups.")

    # Subclasses override the ones they support.
    def lookup_ip(self, ip): return self._unsupported("ip", ip)
    def lookup_domain(self, domain): return self._unsupported("domain", domain)
    def lookup_url(self, url): return self._unsupported("url", url)
    def lookup_hash(self, digest): return self._unsupported("hash", digest)

    def lookup(self, itype: str, indicator: str):
        fn = {"ip": self.lookup_ip, "domain": self.lookup_domain,
              "url": self.lookup_url, "hash": self.lookup_hash}.get(itype)
        if fn is None:
            return ProviderResult.make(self.name, itype, indicator, STATUS_UNSUPPORTED,
                                       reason=f"Unknown indicator type {itype}")
        return fn(indicator)
