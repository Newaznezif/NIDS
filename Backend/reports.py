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
        },
        "executive_summary": _summary(ev, iocs),
        "scope": _scope(ev),
        "indicators": iocs,
        "technical_findings": _technical(ev),
        "threat_intelligence": ti_findings,
        "network_analysis": _network(ev),
        "log_analysis": _logs(ev),
        "detection_evidence": ev["nids_alerts"],
        "timeline": ev["timeline"],
        "analyst_notes": [{"author": n["author"], "created_at": n["created_at"], "body": n["body"]}
                          for n in ev["notes"]],
        "evidence_sources": _sources(ev),
        "disclaimer": (
            "Observed facts are measurements made by this platform (packet capture, DNS/TLS "
            "queries, local file hashing). Calculated values are derived locally from supplied "
            "input. External intelligence is quoted verbatim from the named provider with a "
            "retrieval timestamp and may be incomplete or stale. Analyst notes are interpretation "
            "and are labelled as such. Absence of a threat-intelligence result does not imply an "
            "indicator is safe."
        ),
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

def render_pdf(report: dict) -> bytes:
    doc = PDFDocument(report["cover"]["title"])
    c = report["cover"]
    doc.line(c["platform"], size=18, bold=True)
    doc.line(c["classification"], size=10, bold=True)
    doc.spacer(6)
    doc.line(f"Case ID: {c['case_id']}")
    doc.line(f"Title: {c['title']}")
    doc.line(f"Analyst: {c['analyst']}")
    doc.line(f"Date: {c['date']}")
    doc.line(f"Status / Priority: {c['status']} / {c['priority']}")

    doc.heading("Executive Summary")
    doc.line(report["executive_summary"])

    doc.heading("Scope")
    doc.line(report["scope"])

    doc.heading("Indicators")
    if report["indicators"]:
        for i in report["indicators"]:
            doc.line(f"- [{i['type']}] {i['value']}  ({i['provenance']})", indent=8)
    else:
        doc.line("No indicators attached.")

    doc.heading("Technical Findings")
    if report["technical_findings"]:
        for f in report["technical_findings"]:
            doc.line(f"* {f['type'].upper()}: {f['indicator']}  (investigated {f['investigated_at']})", bold=True)
            for section, val in f["fields"].items():
                doc.line(f"{section}:", indent=8, bold=True)
                _dump(doc, val, indent=16)
    else:
        doc.line("No technical findings recorded.")

    doc.heading("Threat Intelligence")
    if report["threat_intelligence"]:
        for t in report["threat_intelligence"]:
            doc.line(f"* {t['provider']} - {t['indicator']}: {t['status']} (retrieved {t['retrieved_at']})", bold=True)
            _dump(doc, t.get("data", {}), indent=16)
    else:
        doc.line("No external threat-intelligence results returned.")

    doc.heading("Network Analysis (Observed / Scanned)")
    if report["network_analysis"]:
        for n in report["network_analysis"]:
            doc.line(f"* {n['source']}: {n['attack_type']} {n['severity']} "
                     f"{n['source_ip']} -> {n['destination_ip']}:{n['destination_port']}/{n['protocol']}")
            _dump(doc, n.get("evidence", {}), indent=16)
    else:
        doc.line("No network detection evidence attached.")

    doc.heading("Log Analysis")
    if report["log_analysis"]:
        for l in report["log_analysis"]:
            doc.line(f"- {l['label']} ({l['ref']})")
    else:
        doc.line("No log files attached.")

    doc.heading("Timeline")
    for t in report["timeline"]:
        doc.line(f"{t['ts']}  [{t['kind']}] {t['summary']}  ({t['provenance'] or t['source']})", indent=8)
    if not report["timeline"]:
        doc.line("No timeline events recorded.")

    doc.heading("Analyst Assessment (Interpretation)")
    if report["analyst_notes"]:
        for n in report["analyst_notes"]:
            doc.line(f"{n['created_at']} {n['author']}:", bold=True)
            doc.line(n["body"], indent=8)
    else:
        doc.line("No analyst notes recorded.")

    doc.heading("Evidence Sources")
    for s in report["evidence_sources"]:
        doc.line(f"- {s}", indent=8)
    if not report["evidence_sources"]:
        doc.line("No external or observed sources were used.")

    doc.heading("Disclaimer")
    doc.line(report["disclaimer"])

    return doc.render()


def _dump(doc: PDFDocument, obj, indent=8, depth=0):
    if depth > 3:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                doc.line(f"{k}:", indent=indent)
                _dump(doc, v, indent + 8, depth + 1)
            else:
                doc.line(f"{k}: {v}", indent=indent)
    elif isinstance(obj, list):
        for item in obj[:20]:
            if isinstance(item, (dict, list)):
                _dump(doc, item, indent, depth + 1)
            else:
                doc.line(f"- {item}", indent=indent)
    else:
        doc.line(str(obj), indent=indent)


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
