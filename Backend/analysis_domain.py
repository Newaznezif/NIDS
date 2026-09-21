"""Domain investigation orchestrator.

DNS records and the TLS certificate are observed for real by this platform
(OBSERVED). Registration data comes from the public RDAP service when
reachable (EXTERNAL INTELLIGENCE). Threat intelligence comes from configured
providers (EXTERNAL INTELLIGENCE). Anything unavailable is reported as such.
"""
import socket
import ssl

from . import network_tools, providers
from .providers.base import http_get_json
from .analysis_common import field

RDAP_BASE = "https://rdap.org/domain"


def _dns_records(domain: str) -> dict:
    records = {}
    for qtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
        try:
            vals = network_tools.dns_query(domain, qtype)
            records[qtype] = {"records": vals,
                              "provenance": "OBSERVED" if vals else "UNAVAILABLE",
                              "source": f"DNS {qtype} query (platform resolver)"}
        except Exception as e:
            records[qtype] = {"records": [], "provenance": "UNAVAILABLE",
                              "source": f"DNS {qtype} query (platform resolver)", "note": str(e)}
    return records


def _registration(domain: str) -> dict:
    ok, reason = network_tools.ssrf_check(f"{RDAP_BASE}/{domain}")
    if not ok:
        return {"provenance": "UNAVAILABLE", "source": "RDAP", "note": reason}
    try:
        payload = http_get_json(f"{RDAP_BASE}/{domain}")
    except Exception as e:
        return {"provenance": "UNAVAILABLE", "source": "RDAP", "note": f"{type(e).__name__}: {e}"}
    events = {e.get("eventAction"): e.get("eventDate") for e in (payload or {}).get("events", [])}
    entities = (payload or {}).get("entities", [])
    registrar = None
    for ent in entities:
        for role in ent.get("roles", []):
            if role == "registrar":
                vcard = ((ent.get("vcardArray") or [None, []])[1] or [])
                for item in vcard:
                    if item and item[0] == "fn":
                        registrar = item[3]
    out = {
        "registrar": registrar,
        "creation_date": events.get("registration"),
        "expiration_date": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": [n.get("ldhName") for n in (payload or {}).get("nameservers", [])],
        "status": (payload or {}).get("status", []),
    }
    data = {k: v for k, v in out.items() if v not in (None, [], {})}
    if not data:
        return {"provenance": "UNAVAILABLE", "source": "RDAP", "note": "No registration data returned."}
    return {"provenance": "EXTERNAL INTELLIGENCE", "source": "RDAP (rdap.org)", **data}


def _certificate(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
        subj = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        return {
            "provenance": "OBSERVED",
            "source": "TLS handshake (port 443)",
            "subject_cn": subj.get("commonName"),
            "issuer_org": issuer.get("organizationName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [e[1] for e in cert.get("subjectAltName", ())],
        }
    except Exception as e:
        return {"provenance": "UNAVAILABLE", "source": "TLS handshake (port 443)",
                "note": f"No certificate retrieved: {type(e).__name__}: {e}"}


def analyze(domain: str) -> dict:
    from .ioc_engine import is_domain
    valid = is_domain(domain)
    result = {
        "indicator": domain,
        "indicator_type": "DOMAIN",
        "valid": field(valid, "CALCULATED", "local domain validation"),
        "dns": None,
        "resolved_ips": None,
        "registration": None,
        "certificate": None,
        "threat_intelligence": [],
    }
    if not valid:
        result["error"] = "Invalid domain name"
        return result

    result["dns"] = _dns_records(domain)
    result["resolved_ips"] = result["dns"]["A"]["records"]
    result["registration"] = _registration(domain)
    result["certificate"] = _certificate(domain)
    result["threat_intelligence"].extend(providers.query_all("domain", domain))
    for ip in result["resolved_ips"]:
        result["threat_intelligence"].extend(providers.query_all("ip", ip))
    return result
