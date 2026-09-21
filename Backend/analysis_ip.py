"""IP investigation orchestrator.

Combines locally calculated facts (CALCULATED), real resolver observations
(OBSERVED), and configured external intelligence (EXTERNAL INTELLIGENCE).
Ports are reported as PASSIVE INTELLIGENCE only; this platform performs no
active port scanning, so a port is never claimed open.
"""
import ipaddress

from . import network_tools, providers
from .analysis_common import field


def _basic(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return {"valid": field(False, "CALCULATED", "local ipaddress validation"),
                "error": "Invalid IP address"}
    return {
        "valid": field(True, "CALCULATED", "local ipaddress validation"),
        "version": field(addr.version, "CALCULATED", "local ipaddress validation"),
        "is_private": field(addr.is_private, "CALCULATED", "local ipaddress validation"),
        "is_reserved": field(addr.is_reserved, "CALCULATED", "local ipaddress validation"),
        "is_loopback": field(addr.is_loopback, "CALCULATED", "local ipaddress validation"),
        "is_multicast": field(addr.is_multicast, "CALCULATED", "local ipaddress validation"),
        "scope": field("private" if addr.is_private else "public", "CALCULATED", "local ipaddress validation"),
    }


def analyze(ip: str) -> dict:
    result = {
        "indicator": ip,
        "indicator_type": "IPv4" if ":" not in ip else "IPv6",
        "basic": _basic(ip),
        "reverse_dns": None,
        "geolocation": None,
        "threat_intelligence": [],
        "ports": {
            "mode": "PASSIVE INTELLIGENCE ONLY",
            "open_ports": [],
            "note": "No active port scanning is performed. A port is never reported open "
                    "unless a trusted external source states it; none configured here.",
            "provenance": "UNAVAILABLE",
        },
    }
    if not result["basic"]["valid"]["value"]:
        return result

    try:
        ptr = network_tools.reverse_dns(ip)
        result["reverse_dns"] = {
            "records": ptr,
            "provenance": "OBSERVED" if ptr else "UNAVAILABLE",
            "source": "reverse DNS (OS resolver)",
            "note": "" if ptr else "No PTR record returned by resolver.",
        }
    except Exception as e:
        result["reverse_dns"] = {"records": [], "provenance": "UNAVAILABLE",
                                 "source": "reverse DNS (OS resolver)", "note": str(e)}

    for res in providers.query_all("ip", ip):
        if res["provider"].startswith("GeoIP"):
            result["geolocation"] = res
        else:
            result["threat_intelligence"].append(res)

    return result
