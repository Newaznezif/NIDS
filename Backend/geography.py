"""Investigation geography telemetry.

Only artifacts with a real, successfully returned geolocation are recorded.
Nothing is guessed: if a provider did not return coordinates, no row is created
and the map simply does not show the artifact.

The intensity scale represents INVESTIGATION ACTIVITY (how often artifacts in
that area were investigated), never maliciousness or country risk.
"""
import logging
from datetime import datetime, timezone

from . import platform_db

logger = logging.getLogger("NIDS.Geography")

ACTIVITY_LEVELS = ["low", "medium", "high", "very_high"]
ACTIVITY_COLORS = ["#22c55e", "#eab308", "#f97316", "#ef4444"]


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def record_from_investigation(result, itype, value):
    """Record geolocation telemetry when an IP investigation actually returned it."""
    if itype not in ("IPv4", "IPv6"):
        return None
    geo = (result or {}).get("geolocation") or {}
    if geo.get("status") != "OK":
        return None
    data = geo.get("data") or {}
    if data.get("latitude") is None or data.get("longitude") is None:
        return None
    payload = dict(data)
    payload["provider"] = geo.get("provider", "")
    return platform_db.record_geo_artifact(value, "ip", payload, _now_iso())


def backfill_from_investigations():
    """One-time, idempotent reconstruction of telemetry from stored investigations.

    Rows are only inserted when absent; the inserted investigation_count equals
    the number of stored investigations that actually carried geolocation for
    that artifact, so repeated restarts never inflate counts.
    """
    existing = {r["artifact"] for r in platform_db.all_geo_artifacts()}
    counts = {}
    for inv in platform_db.recent_investigations(limit=100000, demo=0):
        if inv["ioc_type"] not in ("IPv4", "IPv6"):
            continue
        full = platform_db.get_investigation(inv["id"])
        if not full:
            continue
        result = full.get("result") or {}
        geo = result.get("geolocation") or {}
        if geo.get("status") != "OK":
            continue
        data = geo.get("data") or {}
        if data.get("latitude") is None or data.get("longitude") is None:
            continue
        key = inv["ioc_value"]
        entry = counts.setdefault(key, {"count": 0, "first": inv["created_at"],
                                        "last": inv["created_at"], "data": data,
                                        "provider": geo.get("provider", "")})
        entry["count"] += 1
        entry["first"] = min(entry["first"], inv["created_at"])
        entry["last"] = max(entry["last"], inv["created_at"])
    added = 0
    conn_rows = []
    for artifact, entry in counts.items():
        if artifact in existing:
            continue
        conn_rows.append(artifact)
        platform_db.record_geo_artifact(artifact, "ip", entry["data"], entry["last"])
        # record_geo_artifact starts the counter at 1; align it with history.
        _set_count(artifact, entry["count"], entry["first"])
        added += 1
    if added:
        logger.info("Geography telemetry backfilled %d artifact(s) from stored investigations.", added)
    return added


def _set_count(artifact, count, first_seen):
    conn = platform_db.get_connection()
    conn.execute(
        "UPDATE geo_artifacts SET investigation_count = ?, first_seen = ? WHERE artifact = ?",
        (max(1, count), first_seen, artifact),
    )
    conn.commit()
    conn.close()


def _level_for(count, max_count):
    if max_count <= 0:
        return 0
    ratio = count / max_count
    if ratio <= 0.25:
        return 0
    if ratio <= 0.50:
        return 1
    if ratio <= 0.75:
        return 2
    return 3


def map_payload(marker_limit=300):
    countries = platform_db.geo_country_aggregate()
    markers = platform_db.geo_markers(limit=marker_limit)
    max_country = max([c["investigations"] for c in countries], default=0)
    max_marker = max([m["investigation_count"] for m in markers], default=0)
    for c in countries:
        lvl = _level_for(c["investigations"], max_country)
        c["activity_level"] = ACTIVITY_LEVELS[lvl]
        c["activity_color"] = ACTIVITY_COLORS[lvl]
    for m in markers:
        lvl = _level_for(m["investigation_count"], max_marker)
        m["activity_level"] = ACTIVITY_LEVELS[lvl]
        m["activity_color"] = ACTIVITY_COLORS[lvl]
    total_investigations = sum(c["investigations"] for c in countries)
    return {
        "countries": countries,
        "markers": markers,
        "totals": {
            "countries": len(countries),
            "unique_artifacts": len(markers),
            "investigations": total_investigations,
        },
        "legend": {
            "meaning": "Investigation activity recorded for this geographic area. "
                       "Intensity reflects how often artifacts were investigated here, "
                       "NOT maliciousness, threat level or country risk.",
            "levels": [
                {"level": ACTIVITY_LEVELS[i], "label": label, "color": ACTIVITY_COLORS[i]}
                for i, label in enumerate(["Low", "Medium", "High", "Very high"])
            ],
        },
        "provenance": "EXTERNAL INTELLIGENCE",
        "generated_at": _now_iso(),
    }
