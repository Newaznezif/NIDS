"""URL investigation orchestrator.

Parses the URL locally (EXTRACTED), resolves the hostname via real DNS
(OBSERVED), then correlates the URL, its domain and resolved IPs against
configured external intelligence (EXTERNAL INTELLIGENCE).
"""
from urllib.parse import urlparse, parse_qsl

from . import network_tools, providers
from .analysis_common import registrable_domain, field


def parse_url(url: str) -> dict:
    try:
        p = urlparse(url)
    except ValueError:
        return {"valid": field(False, "CALCULATED", "local URL parse"), "error": "Unparseable URL"}
    hostname = (p.hostname or "").lower()
    return {
        "valid": field(bool(p.scheme and hostname), "CALCULATED", "local URL parse"),
        "scheme": field(p.scheme or None, "EXTRACTED", "local URL parse"),
        "hostname": field(hostname or None, "EXTRACTED", "local URL parse"),
        "domain": field(registrable_domain(hostname) or None, "CALCULATED", "registrable-domain derivation"),
        "port": field(p.port, "EXTRACTED", "local URL parse"),
        "path": field(p.path or "/", "EXTRACTED", "local URL parse"),
        "query_parameters": field(dict(parse_qsl(p.query)), "EXTRACTED", "local URL parse"),
        "fragment": field(p.fragment or None, "EXTRACTED", "local URL parse"),
        "username": field(p.username, "EXTRACTED", "local URL parse"),
    }


def analyze(url: str) -> dict:
    parsed = parse_url(url)
    result = {
        "indicator": url,
        "indicator_type": "URL",
        "parsed": parsed,
        "resolved_ips": None,
        "threat_intelligence": [],
    }
    if not parsed["valid"]["value"]:
        return result

    hostname = parsed["hostname"]["value"]
    try:
        ips = network_tools.resolve_a(hostname)
        result["resolved_ips"] = {
            "records": ips,
            "provenance": "OBSERVED" if ips else "UNAVAILABLE",
            "source": "DNS A query (platform resolver)",
            "note": "" if ips else "No A record returned.",
        }
    except Exception as e:
        result["resolved_ips"] = {"records": [], "provenance": "UNAVAILABLE",
                                  "source": "DNS A query (platform resolver)", "note": str(e)}

    result["threat_intelligence"].extend(providers.query_all("url", url))
    if parsed["domain"]["value"]:
        result["threat_intelligence"].extend(providers.query_all("domain", parsed["domain"]["value"]))
    for ip in (result["resolved_ips"] or {}).get("records", []):
        result["threat_intelligence"].extend(providers.query_all("ip", ip))

    return result
