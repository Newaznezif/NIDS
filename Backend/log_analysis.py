"""Streaming security-log analyzer.

Files are processed in bounded chunks line-by-line; the full file is never
loaded into memory. Overview/statistics are single-pass aggregations. Search
re-streams the file applying filters, so arbitrarily large logs stay usable.
"""
import re
import json
from collections import Counter
from datetime import datetime, timezone

from . import config
from .ioc_engine import extract_iocs, flatten

_TS_PATTERNS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
    (re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"), "%Y-%m-%d %H:%M:%S"),
    (re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"), "%d/%b/%Y:%H:%M:%S"),
]
_SYSLOG_RE = re.compile(r"^\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}")
_AUTH_FAIL_RE = re.compile(r"failed password|authentication failure|invalid user|login failed|401 |access denied", re.I)
_ERROR_RE = re.compile(r"\berror\b|\bfail(ed|ure)?\b|\bcritical\b|\b500\b|\bdenied\b", re.I)
_WARN_RE = re.compile(r"\bwarn(ing)?\b", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:user|username|user=|for\s+)([A-Za-z0-9._-]{2,32})", re.I)
_HTTP_STATUS_RE = re.compile(r"\bHTTP/\d\.\d\"\s+(\d{3})\b|\bstatus[=:]\s*(\d{3})\b", re.I)


def _iter_lines(path, chunk_size=None):
    chunk_size = chunk_size or config.LOG_STREAM_CHUNK
    buf = ""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                yield line
    if buf:
        yield buf


def _parse_ts(line: str):
    for rx, fmt in _TS_PATTERNS:
        m = rx.search(line)
        if m:
            try:
                return datetime.strptime(m.group(1), fmt)
            except ValueError:
                continue
    m = re.search(r"\b(1[0-9]{9})\b", line)
    if m:
        try:
            return datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc).replace(tzinfo=None)
        except (ValueError, OSError, OverflowError):
            return None
    return None


def _severity(line: str) -> str:
    if _ERROR_RE.search(line):
        return "ERROR"
    if _WARN_RE.search(line):
        return "WARNING"
    return "INFO"


def _event_type(line: str) -> str:
    low = line.lower()
    if "failed password" in low or "authentication" in low or "login" in low or "sudo" in low:
        return "auth"
    if "http" in low or "get " in low or "post " in low or "user-agent" in low:
        return "http"
    if "dns" in low or "query" in low:
        return "dns"
    if "firewall" in low or "drop" in low or "iptables" in low:
        return "firewall"
    return "system"


def analyze(path: str) -> dict:
    """Single-pass streaming overview + statistics + IOC extraction."""
    total = 0
    first_ts = last_ts = None
    src_ips, dst_ips, users, domains, urls = Counter(), Counter(), Counter(), Counter(), Counter()
    statuses, severities, event_types, repeated = Counter(), Counter(), Counter(), Counter()
    auth_failures = errors = 0
    ioc_acc = {}

    for line in _iter_lines(path):
        if not line.strip():
            continue
        total += 1
        ts = _parse_ts(line)
        if ts:
            first_ts = ts if first_ts is None or ts < first_ts else first_ts
            last_ts = ts if last_ts is None or ts > last_ts else last_ts

        ips = _IP_RE.findall(line)
        if ips:
            src_ips[ips[0]] += 1
            for extra in ips[1:]:
                dst_ips[extra] += 1
        um = _USER_RE.search(line)
        if um:
            users[um.group(1)] += 1
        sm = _HTTP_STATUS_RE.search(line)
        if sm:
            statuses[sm.group(1) or sm.group(2)] += 1

        sev = _severity(line)
        severities[sev] += 1
        if sev == "ERROR":
            errors += 1
        if _AUTH_FAIL_RE.search(line):
            auth_failures += 1
        et = _event_type(line)
        event_types[et] += 1
        repeated[line.strip()[:200]] += 1

        ex = extract_iocs(line)
        for key, entries in ex.items():
            bucket = ioc_acc.setdefault(key, Counter())
            for e in entries:
                bucket[e["value"]] += e["occurrences"]
        for dm in re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|uk|de|info|biz)\b", line, re.I):
            domains[dm.lower()] += 1
        for um_ in re.findall(r"https?://\S+", line, re.I):
            urls[um_.strip()] += 1

    duration = (last_ts - first_ts).total_seconds() if (first_ts and last_ts) else 0
    iocs = {k: [{"value": v, "occurrences": n} for v, n in c.most_common(200)] for k, c in ioc_acc.items()}

    return {
        "overview": {
            "total_events": total,
            "time_range": {
                "first": first_ts.isoformat() if first_ts else None,
                "last": last_ts.isoformat() if last_ts else None,
            },
            "duration_seconds": duration,
            "events_per_second": round(total / duration, 3) if duration else None,
            "unique_source_ips": len(src_ips),
            "unique_destination_ips": len(dst_ips),
            "unique_users": len(users),
            "unique_domains": len(domains),
            "unique_urls": len(urls),
            "errors": errors,
            "authentication_failures": auth_failures,
            "provenance": "CALCULATED",
            "source": "streaming single-pass analysis of analyst-provided file",
        },
        "statistics": {
            "top_source_ips": src_ips.most_common(20),
            "top_destination_ips": dst_ips.most_common(20),
            "top_urls": urls.most_common(20),
            "top_domains": domains.most_common(20),
            "top_users": users.most_common(20),
            "http_status_codes": statuses.most_common(20),
            "severity_counts": dict(severities),
            "event_types": dict(event_types),
            "repeated_events": repeated.most_common(10),
        },
        "iocs": flatten(iocs),
    }


def search(path: str, keyword=None, regex=None, ip=None, severity=None,
           event_type=None, start=None, end=None, limit=200):
    """Re-stream the file applying filters; returns matching lines + numbers."""
    pattern = None
    if regex:
        try:
            pattern = re.compile(regex)
        except re.error as e:
            return {"error": f"Invalid regex: {e}", "matches": []}
    start_dt = _iso(start)
    end_dt = _iso(end)
    matches = []
    lineno = 0
    for line in _iter_lines(path):
        lineno += 1
        if not line.strip():
            continue
        if keyword and keyword.lower() not in line.lower():
            continue
        if pattern and not pattern.search(line):
            continue
        if ip and ip not in line:
            continue
        if severity and _severity(line) != severity.upper():
            continue
        if event_type and _event_type(line) != event_type.lower():
            continue
        if start_dt or end_dt:
            ts = _parse_ts(line)
            if start_dt and (ts is None or ts < start_dt):
                continue
            if end_dt and (ts is None or ts > end_dt):
                continue
        matches.append({"line": lineno, "text": line[:1000],
                        "severity": _severity(line), "event_type": _event_type(line)})
        if len(matches) >= limit:
            break
    return {"matches": matches, "truncated": len(matches) >= limit,
            "provenance": "OBSERVED", "source": "analyst-provided log file"}


def _iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def to_json(summary: dict) -> str:
    return json.dumps(summary, indent=2, default=str)
