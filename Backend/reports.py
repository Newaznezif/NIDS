"""Investigation report generator (PDF / JSON / CSV).

Reports are assembled strictly from persisted evidence: case metadata,
attached items, saved investigations, NIDS alerts, analyst notes and the case
timeline. Every section states its provenance. The disclaimer separates
observed facts, calculated values, external intelligence and analyst
interpretation.
"""
import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone

from . import config, platform_db, database
from .pdf_writer import PDFDocument


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def gather_case_evidence(case_db_id: int) -> dict:
    case = platform_db.get_case(case_db_id)
    if not case:
        return {}
    items = platform_db.case_items(case_db_id)
    notes = platform_db.case_notes(case_db_id)
    timeline = platform_db.case_timeline(case_db_id)

    investigations = []
    alerts = []
    for item in items:
        if item["item_type"] == "investigation":
            try:
                inv = platform_db.get_investigation(int(item["item_ref"]))
                if inv:
                    investigations.append(inv)
            except (ValueError, TypeError):
                continue
        elif item["item_type"] == "alert":
            try:
                al = database.get_alert(int(item["item_ref"]))
                if al:
                    alerts.append(al)
            except (ValueError, TypeError):
                continue

    return {
        "case": case,
        "items": items,
        "notes": notes,
        "timeline": timeline,
        "investigations": investigations,
        "nids_alerts": alerts,
        "generated_at": _now(),
        "classification": config.REPORT_CLASSIFICATION,
    }


def build_report(case_db_id: int, analyst: str = "") -> dict:
    ev = gather_case_evidence(case_db_id)
    if not ev:
        return {}
    case = ev["case"]

    iocs = []
    for item in ev["items"]:
        if item["item_type"] in ("ip", "url", "domain", "hash", "ioc"):
            iocs.append({"type": item["item_type"], "value": item["item_ref"],
                         "label": item["label"], "provenance": item["provenance"]})

    ti_findings = []
    for inv in ev["investigations"]:
        for res in (inv["result"].get("threat_intelligence") or []):
            ti_findings.append({
                "provider": res.get("provider"),
                "indicator": res.get("indicator"),
                "status": res.get("status"),
                "retrieved_at": res.get("retrieved_at"),
                "data": res.get("data", {}),
            })

    return {
        "cover": {
            "platform": "Cybersecurity Analyst Workbench",
            "case_id": case["case_id"],
            "title": case["title"],
            "analyst": analyst or case["analyst"],
            "date": ev["generated_at"],
            "classification": ev["classification"],
            "status": case["status"],
            "priority": case["priority"],
            "report_type": "Case Investigation Report",
        },
        "executive_summary": _summary(ev, iocs),
        "scope": _scope(ev),
        "indicators": iocs,
        "technical_findings": _technical(ev),
        "threat_intelligence": ti_findings,
        "network_analysis": _network(ev),
        "log_analysis": _logs(ev),
        "detection_evidence": ev["nids_alerts"],
        "evidence_items": [{"type": i["item_type"], "ref": i["item_ref"], "label": i["label"],
                            "provenance": i["provenance"], "added_at": i["added_at"]}
                           for i in ev["items"]],
        "geographic": _geographic(ev),
        "timeline": ev["timeline"],
        "analyst_notes": [{"author": n["author"], "created_at": n["created_at"], "body": n["body"]}
                          for n in ev["notes"]],
        "risk_context": _risk_context(ev, iocs),
        "recommendations": _recommendations(ev),
        "evidence_sources": _sources(ev),
        "metadata": _metadata(ev, iocs),
        "disclaimer": (
            "Observed facts are measurements made by this platform (packet capture, DNS/TLS "
            "queries, local file hashing). Calculated values are derived locally from supplied "
            "input. External intelligence is quoted verbatim from the named provider with a "
            "retrieval timestamp and may be incomplete or stale. Analyst notes are interpretation "
            "and are labelled as such. Absence of a threat-intelligence result does not imply an "
            "indicator is safe."
        ),
    }


def _geographic(ev) -> list:
    """Geolocation rows ONLY where a provider actually returned coordinates.
    Nothing is inferred or fabricated; missing geolocation is simply absent."""
    rows = []
    for inv in ev["investigations"]:
        geo = (inv["result"] or {}).get("geolocation")
        if not isinstance(geo, dict) or geo.get("status") != "OK":
            continue
        d = geo.get("data") or {}
        if d.get("latitude") is None or d.get("longitude") is None:
            continue
        rows.append({
            "indicator": inv["ioc_value"],
            "country": d.get("country") or "Unavailable",
            "country_code": d.get("country_code") or "",
            "region": d.get("region") or "",
            "city": d.get("city") or "",
            "latitude": d.get("latitude"),
            "longitude": d.get("longitude"),
            "asn": str(d.get("asn") or "") or "Unavailable",
            "organization": d.get("organization") or d.get("isp") or "Unavailable",
            "provider": geo.get("provider") or "",
            "provenance": "EXTERNAL INTELLIGENCE",
        })
    return rows


_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _risk_context(ev, iocs) -> dict:
    """Risk context derived strictly from attached evidence. Empty when there is
    no observed detection or external intelligence to describe."""
    alerts = ev["nids_alerts"]
    counts = {}
    for a in alerts:
        sev = (a.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    ti_ok = sum(1 for inv in ev["investigations"]
                for r in (inv["result"].get("threat_intelligence") or []) if r.get("status") == "OK")
    if not alerts and not ti_ok:
        return {}
    highest = "INFO"
    for sev in counts:
        if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(highest, 0):
            highest = sev
    return {
        "observed_detections": len(alerts),
        "severity_counts": counts,
        "highest_observed_severity": highest,
        "external_intel_results": ti_ok,
        "indicators": len(iocs),
        "statement": (
            f"This case carries {len(alerts)} observed NIDS detection(s) and {ti_ok} external "
            f"threat-intelligence result(s) that returned data. The highest severity observed in "
            f"attached evidence is {highest}. Risk context reflects only the evidence attached to "
            f"this case and is not a network-wide assessment."
        ),
    }


def _recommendations(ev) -> list:
    """Actionable, evidence-bound recommendations. Each references a real value
    from the attached evidence; the section is omitted when nothing supports it."""
    recs = []
    seen = set()
    for a in ev["nids_alerts"]:
        sev = (a.get("severity") or "").upper()
        src = a.get("source_ip")
        if sev in ("CRITICAL", "HIGH") and src and src not in seen:
            seen.add(src)
            recs.append({
                "action": f"Review traffic from {src} and consider blocking or rate-limiting it.",
                "basis": f"Observed {a.get('attack_type')} ({sev}) in attached NIDS evidence.",
                "provenance": "OBSERVED",
            })
    for inv in ev["investigations"]:
        for r in (inv["result"].get("threat_intelligence") or []):
            if r.get("status") == "OK":
                recs.append({
                    "action": f"Corroborate the {r.get('provider')} result for {r.get('indicator')} "
                              f"before applying enforcement.",
                    "basis": f"External intelligence returned data (retrieved {r.get('retrieved_at')}).",
                    "provenance": "EXTERNAL INTELLIGENCE",
                })
    return recs


def _metadata(ev, iocs) -> dict:
    case = ev["case"]
    return {
        "case_id": case["case_id"],
        "case_db_id": case.get("id"),
        "generated_at": ev["generated_at"],
        "analyst": case.get("analyst") or "",
        "classification": ev["classification"] or "",
        "evidence_items": len(ev["items"]),
        "indicators": len(iocs),
        "saved_investigations": len(ev["investigations"]),
        "nids_detections": len(ev["nids_alerts"]),
        "analyst_notes": len(ev["notes"]),
        "timeline_events": len(ev["timeline"]),
        "schema_version": "2.0",
        "generator": "Cybersecurity Analyst Platform report engine",
    }


def _summary(ev, iocs) -> str:
    case = ev["case"]
    n_alerts = len(ev["nids_alerts"])
    n_ti = sum(1 for inv in ev["investigations"]
               for r in (inv["result"].get("threat_intelligence") or []) if r.get("status") == "OK")
    return (
        f"Case {case['case_id']} ('{case['title']}') was opened by {case['analyst'] or 'an analyst'} "
        f"on {case['created_at']}. The investigation attached {len(ev['items'])} evidence item(s), "
        f"{len(iocs)} indicator(s), {len(ev['investigations'])} saved investigation(s) and "
        f"{n_alerts} NIDS detection(s). {n_ti} external threat-intelligence result(s) returned data. "
        f"All statements below are traceable to the evidence sources listed at the end of this report."
    )


def _scope(ev) -> str:
    types = sorted({i["item_type"] for i in ev["items"]})
    return ("Investigated indicators and evidence types: " + ", ".join(types) + ". "
            + (ev["case"].get("description") or "No further scope description provided."))


def _technical(ev) -> list:
    findings = []
    for inv in ev["investigations"]:
        res = inv["result"]
        entry = {
            "indicator": inv["ioc_value"],
            "type": inv["ioc_type"],
            "investigated_at": inv["created_at"],
            "fields": {},
        }
        for section in ("basic", "parsed", "hash_type", "geolocation", "reverse_dns", "resolved_ips"):
            val = res.get(section)
            if isinstance(val, dict):
                entry["fields"][section] = val
        findings.append(entry)
    return findings


def _network(ev) -> list:
    out = []
    for al in ev["nids_alerts"]:
        out.append({
            "source": "Observed by NIDS",
            "attack_type": al.get("attack_type"),
            "severity": al.get("severity"),
            "source_ip": al.get("source_ip"),
            "destination_ip": al.get("destination_ip"),
            "destination_port": al.get("destination_port"),
            "protocol": al.get("protocol"),
            "first_seen": al.get("first_seen"),
            "last_seen": al.get("last_seen"),
            "evidence": al.get("evidence", {}),
        })
    return out


def _logs(ev) -> list:
    return [{"item_type": i["item_type"], "label": i["label"], "ref": i["item_ref"]}
            for i in ev["items"] if i["item_type"] == "log"]


def _sources(ev) -> list:
    sources = set()
    for inv in ev["investigations"]:
        for r in (inv["result"].get("threat_intelligence") or []):
            if r.get("status") == "OK":
                sources.add(f"{r.get('provider')} (external intelligence, retrieved {r.get('retrieved_at')})")
            else:
                sources.add(f"{r.get('provider')} ({r.get('status')})")
        for section in ("reverse_dns", "resolved_ips", "dns", "certificate"):
            val = inv["result"].get(section)
            if isinstance(val, dict) and val.get("source"):
                sources.add(f"{val['source']} (observed)")
    for al in ev["nids_alerts"]:
        sources.add("NIDS packet capture (observed)")
    for i in ev["items"]:
        if i["item_type"] in ("file", "log"):
            sources.add(f"Analyst-provided file: {i['label']}")
    return sorted(sources)


# --- renderers ---

_SEV_COLOR = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b",
    "LOW": "#22c55e", "INFO": "#3b82f6",
}
_PROV_COLOR = {
    "OBSERVED": "#2563eb", "CALCULATED": "#16a34a", "EXTRACTED": "#16a34a",
    "EXTERNAL INTELLIGENCE": "#7c3aed", "INFERRED": "#7c3aed",
    "USER PROVIDED": "#d97706", "USER-PROVIDED": "#d97706", "UNAVAILABLE": "#94a3b8",
}


def _sev_badge(sev):
    s = (sev or "INFO").upper()
    return {"text": s, "color": _SEV_COLOR.get(s, "#3b82f6"), "badge": True}


def _prov(prov):
    p = (prov or "UNAVAILABLE").upper()
    return {"text": p, "color": _PROV_COLOR.get(p, "#94a3b8"), "badge": True}


def _flatten(obj, prefix=""):
    """Walk a result dict into (label, value, provenance) leaf tuples."""
    out = []
    if isinstance(obj, dict):
        if "value" in obj and "provenance" in obj:
            out.append((prefix or "value", str(obj.get("value")), obj.get("provenance")))
            return out
        for k, v in obj.items():
            if k in ("provenance", "source"):
                continue
            label = f"{prefix}.{k}" if prefix else k
            out.extend(_flatten(v, label))
    elif isinstance(obj, list):
        for idx, v in enumerate(obj[:20]):
            out.extend(_flatten(v, f"{prefix}[{idx}]"))
    else:
        if obj is not None and str(obj) != "":
            out.append((prefix or "value", str(obj), None))
    return out


def render_pdf(report: dict) -> bytes:
    from . import branding
    doc = PDFDocument(report["cover"]["title"])
    doc.cover(report["cover"])

    # 1. Executive Summary
    doc.section("Executive Summary")
    doc.line(report["executive_summary"], size=10)

    # 2. Investigation Overview
    doc.section("Investigation Overview")
    c = report["cover"]
    doc.label_value([
        ("Investigation ID", c["case_id"]),
        ("Case title", c["title"] or "Unavailable"),
        ("Analyst", c["analyst"] or "Unavailable"),
        ("Report status", c["status"] or "Unavailable"),
        ("Priority", c["priority"] or "Unavailable"),
    ], label_w=130)
    if c.get("classification"):
        doc.label_value([("Classification", c["classification"])], label_w=130)
    doc.spacer(2)
    doc.line(report["scope"], size=9.5, color=branding.MUTED)

    # 3. Artifact Information
    if report["indicators"]:
        doc.section("Artifact Information")
        doc.table(["Type", "Value", "Provenance"],
                  [[i["type"].upper(), i["value"], _prov(i["provenance"])] for i in report["indicators"]],
                  widths=[80, 300, 124], aligns=["left", "left", "center"])

    # 4. Findings
    if report["technical_findings"]:
        doc.section("Findings")
        for f in report["technical_findings"]:
            doc.subheading(f"{f['type'].upper()} \u2014 {f['indicator']}")
            doc.line(f"Investigated {f['investigated_at']}", size=8.5, color=branding.MUTED)
            rows = []
            for section, val in f["fields"].items():
                for label, value, prov in _flatten(val, section):
                    rows.append([label, value, _prov(prov) if prov else {"text": "OBSERVED", "color": "#2563eb", "badge": True}])
            if rows:
                doc.table(["Field", "Value", "Provenance"], rows,
                          widths=[150, 240, 114], aligns=["left", "left", "center"])
            else:
                doc.line("No structured fields returned for this artifact.", size=9, color=branding.MUTED)
            doc.spacer(4)

    # 5. Evidence
    if report["detection_evidence"] or report["log_analysis"] or report.get("evidence_items"):
        doc.section("Evidence")
        if report.get("evidence_items"):
            doc.subheading("Attached evidence items")
            doc.table(["Type", "Reference", "Label", "Provenance", "Added"],
                      [[e["type"].upper(), e["ref"], e["label"] or "", _prov(e["provenance"]), e["added_at"]]
                       for e in report["evidence_items"]],
                      widths=[70, 150, 120, 96, 108], aligns=["left", "left", "left", "center", "left"])
        if report["detection_evidence"]:
            doc.subheading("Observed NIDS detections")
            doc.table(["Severity", "Attack type", "Source", "Destination", "Proto", "First seen"],
                      [[_sev_badge(n.get("severity")), n.get("attack_type", ""),
                        n.get("source_ip", ""), f"{n.get('destination_ip','')}:{n.get('destination_port','')}",
                        n.get("protocol", ""), n.get("first_seen", "")]
                       for n in report["detection_evidence"]],
                      widths=[78, 110, 100, 130, 44, 110],
                      aligns=["center", "left", "left", "left", "left", "left"])
        if report["log_analysis"]:
            doc.subheading("Attached log evidence")
            doc.table(["Label", "Reference"],
                      [[l.get("label", ""), l.get("ref", "")] for l in report["log_analysis"]],
                      widths=[260, 244])

    # 6. Intelligence / Enrichment
    if report["threat_intelligence"]:
        doc.section("Intelligence / Enrichment")
        doc.line("External intelligence is quoted verbatim from the named provider and is labelled "
                 "EXTERNAL INTELLIGENCE. It is not observed network evidence.", size=8.5, color=branding.MUTED)
        for t in report["threat_intelligence"]:
            doc.subheading(f"{t['provider']} \u2014 {t['indicator']}")
            doc.line(f"Status: {t['status']}   Retrieved: {t['retrieved_at']}", size=8.5, color=branding.MUTED)
            rows = [[label, value] for label, value, _p in _flatten(t.get("data", {}))]
            if rows:
                doc.table(["Field", "Value"], rows, widths=[180, 324])
            else:
                doc.line("No data returned by this provider for the indicator.", size=9, color=branding.MUTED)
            doc.spacer(4)

    # 7. Geographic Information
    if report["geographic"]:
        doc.section("Geographic Information")
        doc.line("Geolocation is EXTERNAL INTELLIGENCE returned by the named provider for the "
                 "investigated artifact. Coordinates are reported as returned; nothing is estimated. "
                 "A structured summary is provided in place of a map image.", size=8.5, color=branding.MUTED)
        doc.table(["Indicator", "Country", "City", "ASN", "Organization", "Lat", "Lon"],
                  [[g["indicator"], g["country"], g["city"] or "Unavailable", g["asn"],
                    g["organization"], g["latitude"], g["longitude"]] for g in report["geographic"]],
                  widths=[92, 92, 84, 60, 96, 40, 40],
                  aligns=["left", "left", "left", "left", "left", "right", "right"])
        doc.spacer(2)
        for g in report["geographic"]:
            doc.line(f"{g['indicator']} \u2014 provider {g['provider'] or 'Unavailable'} "
                     f"({g['provenance']}); region {g['region'] or 'Unavailable'}; "
                     f"country code {g['country_code'] or 'Unavailable'}.", size=8.5, color=branding.MUTED)

    # 8. Timeline
    if report["timeline"]:
        doc.section("Timeline")
        doc.table(["When", "Kind", "Summary", "Provenance"],
                  [[t["ts"], t["kind"], t["summary"], _prov(t.get("provenance") or t.get("source"))]
                   for t in report["timeline"]],
                  widths=[110, 70, 220, 104], aligns=["left", "left", "left", "center"])

    # 9. Analyst Notes
    if report["analyst_notes"]:
        doc.section("Analyst Notes")
        doc.line("Analyst notes are interpretation, labelled USER PROVIDED, and are distinct from "
                 "observed or calculated facts.", size=8.5, color=branding.MUTED)
        for n in report["analyst_notes"]:
            doc.subheading(f"{n['author']} \u2014 {n['created_at']}")
            doc.line(n["body"], size=9.5)
            doc.spacer(3)

    # 10. Impact / Risk Context
    if report.get("risk_context"):
        doc.section("Impact / Risk Context")
        rc = report["risk_context"]
        doc.line(rc["statement"], size=10)
        doc.spacer(2)
        sev_rows = [[_sev_badge(sev), str(cnt)] for sev, cnt in
                    sorted(rc["severity_counts"].items(), key=lambda kv: -_SEV_ORDER.get(kv[0], 0))]
        if sev_rows:
            doc.table(["Severity", "Observed detections"], sev_rows, widths=[160, 160],
                      aligns=["center", "left"])

    # 11. Recommendations
    if report.get("recommendations"):
        doc.section("Recommendations")
        doc.table(["Recommended action", "Evidence basis", "Provenance"],
                  [[r["action"], r["basis"], _prov(r["provenance"])] for r in report["recommendations"]],
                  widths=[210, 200, 94], aligns=["left", "left", "center"])

    # 12. Data Provenance
    doc.section("Data Provenance")
    doc.line("Provenance legend:", size=9.5, bold=True)
    legend = [("OBSERVED", "Measured directly by this platform (capture, DNS, hashing)."),
              ("CALCULATED", "Derived locally from supplied input."),
              ("EXTERNAL INTELLIGENCE", "Quoted from a named provider with a retrieval timestamp."),
              ("USER PROVIDED", "Analyst-supplied interpretation or attachment."),
              ("UNAVAILABLE", "No data was returned; never fabricated.")]
    doc.table(["Label", "Meaning"],
              [[{"text": k, "color": _PROV_COLOR.get(k, "#94a3b8"), "badge": True}, v] for k, v in legend],
              widths=[150, 354], aligns=["center", "left"])
    if report["evidence_sources"]:
        doc.subheading("Sources used")
        for s in report["evidence_sources"]:
            doc.line(f"\u2022 {s}", size=9, indent=8)
    doc.spacer(3)
    doc.line(report["disclaimer"], size=8.5, color=branding.MUTED, italic=True)

    # 13. Report Metadata
    doc.section("Report Metadata")
    md = report["metadata"]
    doc.label_value([
        ("Investigation ID", md["case_id"]),
        ("Generated (UTC)", md["generated_at"]),
        ("Analyst", md["analyst"] or "Unavailable"),
        ("Classification", md["classification"] or "Not configured"),
        ("Evidence items", str(md["evidence_items"])),
        ("Indicators", str(md["indicators"])),
        ("Saved investigations", str(md["saved_investigations"])),
        ("NIDS detections", str(md["nids_detections"])),
        ("Analyst notes", str(md["analyst_notes"])),
        ("Timeline events", str(md["timeline_events"])),
        ("Report schema", md["schema_version"]),
        ("Generator", md["generator"]),
    ], label_w=150)

    return doc.render()


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)


def render_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["section", "field", "value", "provenance"])
    for i in report["indicators"]:
        w.writerow(["indicator", i["type"], i["value"], i["provenance"]])
    for t in report["threat_intelligence"]:
        w.writerow(["threat_intelligence", t["provider"], t["indicator"], t["status"]])
    for n in report["network_analysis"]:
        w.writerow(["network", n["attack_type"],
                    f"{n['source_ip']}->{n['destination_ip']}:{n['destination_port']}", "OBSERVED"])
    for g in report.get("geographic", []):
        w.writerow(["geographic", g["indicator"],
                    f"{g['country']}|{g['city']}|{g['latitude']},{g['longitude']}", g["provenance"]])
    for e in report["timeline"]:
        w.writerow(["timeline", e["kind"], e["summary"], e["provenance"] or e["source"]])
    return buf.getvalue()


def generate(case_db_id: int, fmt: str, analyst: str = "") -> dict:
    report = build_report(case_db_id, analyst)
    if not report:
        return {"error": "Case not found"}
    fmt = (fmt or "pdf").lower()
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    stem = f"{report['cover']['case_id']}_{uuid.uuid4().hex[:8]}"
    if fmt == "pdf":
        blob = render_pdf(report)
        ext = ".pdf"
    elif fmt == "json":
        blob = render_json(report).encode("utf-8")
        ext = ".json"
    elif fmt == "csv":
        blob = render_csv(report).encode("utf-8")
        ext = ".csv"
    else:
        return {"error": f"Unsupported report format '{fmt}'"}
    stored = stem + ext
    with open(os.path.join(config.REPORT_DIR, stored), "wb") as fh:
        fh.write(blob)
    platform_db.save_report(case_db_id, fmt, stored, analyst)
    return {"stored_name": stored, "format": fmt, "bytes": len(blob), "report": report}
