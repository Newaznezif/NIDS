"""IOC type detection and extraction engine.

Pure, deterministic text processing: every extracted indicator is a literal
substring of the supplied input, with an occurrence count. Nothing is inferred
beyond format classification, and classification is reported as CALCULATED.
"""
import re
import ipaddress
from collections import Counter
from typing import Dict, List, Any

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){7}:|\b::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b")
_URL_RE = re.compile(r"\b(?:https?|ftp|ftps|smtp|imap|pop3|ws|wss)://[^\s<>\"'`,;)\]]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.IGNORECASE)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA512_RE = re.compile(r"\b[a-fA-F0-9]{128}\b")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}


def is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except (ValueError, TypeError):
        return False


def is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except (ValueError, TypeError):
        return False


def hash_type(value: str) -> str:
    v = (value or "").strip()
    if not re.fullmatch(r"[a-fA-F0-9]+", v):
        return "UNKNOWN"
    return HASH_LENGTHS.get(len(v), "UNKNOWN")


def is_domain(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v or is_ipv4(v) or is_ipv6(v):
        return False
    return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", v))


def detect_type(value: str) -> str:
    """Classify a single indicator string. Returns a type label or UNKNOWN."""
    v = (value or "").strip()
    if not v:
        return "UNKNOWN"
    if is_ipv4(v):
        return "IPv4"
    if is_ipv6(v):
        return "IPv6"
    if re.fullmatch(r"[a-fA-F0-9]+", v):
        ht = HASH_LENGTHS.get(len(v))
        if ht:
            return ht
    if _CVE_RE.fullmatch(v):
        return "CVE"
    if _EMAIL_RE.fullmatch(v):
        return "EMAIL"
    if re.fullmatch(r"(?:https?|ftp|ftps|ws|wss)://\S+", v, re.IGNORECASE):
        return "URL"
    if is_domain(v):
        return "DOMAIN"
    return "UNKNOWN"


def _counts(values: List[str]) -> List[Dict[str, Any]]:
    c = Counter(values)
    return [
        {"value": v, "occurrences": n}
        for v, n in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def extract_iocs(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """Extract and deduplicate indicators from arbitrary text, with counts."""
    text = text or ""

    urls = _URL_RE.findall(text)
    # Strip URLs and IPs before domain matching so hostnames inside URLs and
    # dotted-quad IPs are not double-counted as bare domains.
    stripped = _URL_RE.sub(" ", text)
    ipv4 = [m for m in _IPV4_RE.findall(stripped) if is_ipv4(m)]
    stripped_ips = _IPV4_RE.sub(" ", stripped)
    ipv6 = [m for m in _IPV6_RE.findall(stripped_ips) if is_ipv6(m)]
    stripped_ips = _IPV6_RE.sub(" ", stripped_ips)

    domains = [m.lower() for m in _DOMAIN_RE.findall(stripped_ips) if is_domain(m)]
    # Exclude domains that are merely the host of an extracted URL.
    url_hosts = set()
    for u in urls:
        m = re.match(r"[a-z]+://(?:[^@/]+@)?([^:/?#]+)", u, re.IGNORECASE)
        if m:
            url_hosts.add(m.group(1).lower())
    domains = [d for d in domains if d not in url_hosts]

    sha512 = _SHA512_RE.findall(text)
    masked = _SHA512_RE.sub(" ", text)
    sha256 = _SHA256_RE.findall(masked)
    masked = _SHA256_RE.sub(" ", masked)
    sha1 = _SHA1_RE.findall(masked)
    masked = _SHA1_RE.sub(" ", masked)
    md5 = _MD5_RE.findall(masked)

    return {
        "ipv4": _counts(ipv4),
        "ipv6": _counts(ipv6),
        "url": _counts(urls),
        "domain": _counts(domains),
        "md5": _counts(md5),
        "sha1": _counts(sha1),
        "sha256": _counts(sha256),
        "sha512": _counts(sha512),
        "email": _counts(_EMAIL_RE.findall(text)),
        "cve": _counts([m.upper() for m in _CVE_RE.findall(text)]),
    }


def flatten(extracted: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Flatten extraction result into a single ordered list with types."""
    type_map = {
        "ipv4": "IPv4", "ipv6": "IPv6", "url": "URL", "domain": "DOMAIN",
        "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "sha512": "SHA512",
        "email": "EMAIL", "cve": "CVE",
    }
    out = []
    for key, label in type_map.items():
        for entry in extracted.get(key, []):
            out.append({"type": label, "value": entry["value"], "occurrences": entry["occurrences"]})
    out.sort(key=lambda e: (-e["occurrences"], e["type"], e["value"]))
    return out
