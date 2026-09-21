"""Cybersecurity Analyst Workbench routes (Blueprint).

All /api/wb/* endpoints require an authenticated session and are rate-limited
and audited. The legacy NIDS /api/* endpoints are unchanged.
"""
import os
import re
from datetime import datetime

from flask import Blueprint, jsonify, request, session, send_from_directory, redirect, url_for, render_template_string

from . import config, platform_db, security
from . import ioc_engine, encoding_tools, network_tools
from . import analysis_ip, analysis_url, analysis_domain, analysis_hash
from . import file_analysis, log_analysis, reports, demo_data, providers

wb = Blueprint("workbench", __name__)

LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Analyst Workbench - Login</title>
<style>
body{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:#0b1220;color:#e5e7eb;
display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#111a2e;border:1px solid #1f2a44;border-radius:10px;padding:36px;width:380px}
h1{font-size:20px;margin:0 0 4px} .sub{color:#8b98b8;font-size:12px;margin-bottom:24px}
label{display:block;font-size:11px;letter-spacing:.08em;color:#8b98b8;margin:14px 0 6px;text-transform:uppercase}
input{width:100%;box-sizing:border-box;background:#0b1220;border:1px solid #26324f;border-radius:6px;
color:#e5e7eb;padding:10px 12px;font-size:14px}
button{margin-top:22px;width:100%;background:#0e7490;border:none;color:#fff;padding:12px;
border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#0891b2}
.err{color:#f87171;font-size:12px;margin-top:12px;min-height:16px}
.feat{margin-top:26px;border-top:1px solid #1f2a44;padding-top:16px;font-size:12px;color:#8b98b8;line-height:1.7}
</style></head><body><div class="card">
<h1>Cybersecurity Analyst Workbench</h1>
<div class="sub">Real evidence &middot; traceable results &middot; professional reporting</div>
<form method="post" action="/api/wb/login">
<label>Username</label><input name="username" autocomplete="username" required>
<label>Password</label><input name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
<div class="err">{{ error }}</div>
</form>
<div class="feat">
IOC investigation &middot; threat-intelligence lookups &middot; log &amp; file analysis &middot;
IOC extraction &middot; encoding tools &middot; network analysis &middot; investigation cases &middot;
evidence timeline &middot; PDF/JSON/CSV reporting &middot; integrated NIDS network monitoring.
<br><br>No result is ever fabricated. Unconfigured sources report NOT CONFIGURED.
</div>
</div></body></html>"""


@wb.before_request
def _guard():
    if security.rate_limit_exceeded():
        return jsonify({"error": "Rate limit exceeded. Slow down."}), 429


# --- pages ---

@wb.route("/login", methods=["GET"])
def login_page():
    if session.get("user"):
        return redirect(url_for("workbench.workbench_page"))
    return render_template_string(LOGIN_PAGE, error="")


@wb.route("/workbench", methods=["GET"])
@security.login_required
def workbench_page():
    from .app import FRONTEND_DIR
    return send_from_directory(FRONTEND_DIR, "workbench.html")


# --- auth ---

@wb.route("/api/wb/login", methods=["POST"])
def login():
    username = (request.form.get("username") or (request.get_json(silent=True) or {}).get("username") or "").strip()
    password = request.form.get("password") or (request.get_json(silent=True) or {}).get("password") or ""
    if security.authenticate(username, password):
        session.clear()
        session["user"] = username
        session.permanent = True
        security.audit_event("login", f"user={username}")
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"authenticated": True, "user": username}), 200
        return redirect(url_for("workbench.workbench_page"))
    security.audit_event("login_failed", f"user={username}")
    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({"authenticated": False, "error": "Invalid credentials."}), 401
    return render_template_string(LOGIN_PAGE, error="Invalid username or password."), 401


@wb.route("/api/wb/logout", methods=["POST"])
def logout():
    user = session.get("user", "")
    security.audit_event("logout", f"user={user}")
    session.clear()
    return jsonify({"authenticated": False}), 200


@wb.route("/api/wb/session", methods=["GET"])
def session_info():
    return jsonify({"authenticated": bool(session.get("user")), "user": session.get("user", "")}), 200


# --- dashboard ---

@wb.route("/api/wb/dashboard", methods=["GET"])
@security.api_login_required
def dashboard():
    cases = platform_db.list_cases(demo=0)
    invs = platform_db.recent_investigations(limit=20, demo=0)
    from .database import get_all_alerts, get_stats
    ioc_counter = {}
    for inv in invs:
        ioc_counter[inv["ioc_type"]] = ioc_counter.get(inv["ioc_type"], 0) + 1
    return jsonify({
        "active_cases": [c for c in cases if c["status"] in ("OPEN", "IN_PROGRESS")],
        "recent_cases": cases[:10],
        "recent_investigations": invs,
        "recent_alerts": get_all_alerts(limit=10),
        "ioc_statistics": ioc_counter,
        "analysis_activity": platform_db.recent_audit(limit=15),
        "providers": providers.provider_statuses(),
        "recent_reports": platform_db.recent_reports(limit=10),
        "nids": get_stats(),
    }), 200


# --- investigation center ---

@wb.route("/api/wb/investigate", methods=["POST"])
@security.api_login_required
def investigate():
    payload = request.get_json(silent=True) or {}
    value = (payload.get("value") or "").strip()
    if not value:
        return jsonify({"error": "value is required"}), 400
    itype = ioc_engine.detect_type(value)
    if itype == "UNKNOWN":
        return jsonify({"error": "Unrecognized indicator type. Provide an IP, URL, domain, "
                                 "or MD5/SHA1/SHA256/SHA512 hash.", "detected_type": "UNKNOWN"}), 400
    if itype in ("IPv4", "IPv6"):
        result = analysis_ip.analyze(value)
    elif itype == "URL":
        result = analysis_url.analyze(value)
    elif itype == "DOMAIN":
        result = analysis_domain.analyze(value)
    elif itype in ("MD5", "SHA1", "SHA256", "SHA512"):
        result = analysis_hash.analyze(value)
    else:
        return jsonify({"error": f"No analyzer for type {itype}", "detected_type": itype}), 400

    inv_id = platform_db.save_investigation(itype, value, result, analyst=security.current_user())
    security.audit_event("investigate", f"{itype}:{value}")
    return jsonify({"detected_type": itype, "investigation_id": inv_id, "result": result}), 200


@wb.route("/api/wb/investigations", methods=["GET"])
@security.api_login_required
def investigations():
    return jsonify({"investigations": platform_db.recent_investigations(limit=100, demo=0)}), 200


@wb.route("/api/wb/investigation/<int:inv_id>", methods=["GET"])
@security.api_login_required
def investigation(inv_id):
    inv = platform_db.get_investigation(inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found"}), 404
    return jsonify(inv), 200


# --- IOC extraction ---

@wb.route("/api/wb/ioc/extract", methods=["POST"])
@security.api_login_required
def extract():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text") or ""
    extracted = ioc_engine.extract_iocs(text)
    return jsonify({"extracted": extracted, "flat": ioc_engine.flatten(extracted),
                    "provenance": "EXTRACTED",
                    "source": payload.get("source", "analyst-provided text")}), 200


# --- encoding ---

@wb.route("/api/wb/encode", methods=["POST"])
@security.api_login_required
def encode():
    payload = request.get_json(silent=True) or {}
    try:
        out = encoding_tools.run(payload.get("operation"), payload.get("codec"), payload.get("data", ""))
    except encoding_tools.CodecError as e:
        return jsonify({"error": str(e)}), 400
    security.audit_event("encode", f"{payload.get('operation')}/{payload.get('codec')}")
    return jsonify(out), 200


# --- network tools ---

@wb.route("/api/wb/network/cidr", methods=["POST"])
@security.api_login_required
def net_cidr():
    payload = request.get_json(silent=True) or {}
    return jsonify(network_tools.cidr_analysis(payload.get("cidr", ""))), 200


@wb.route("/api/wb/network/dns", methods=["POST"])
@security.api_login_required
def net_dns():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    qtype = (payload.get("qtype") or "A").upper()
    if not name:
        return jsonify({"error": "name is required"}), 400
    try:
        records = network_tools.dns_query(name, qtype)
        return jsonify({"name": name, "qtype": qtype, "records": records,
                        "provenance": "OBSERVED" if records else "UNAVAILABLE",
                        "source": "DNS query (platform resolver)"}), 200
    except network_tools.DnsError as e:
        return jsonify({"name": name, "qtype": qtype, "records": [],
                        "provenance": "UNAVAILABLE", "source": "DNS query (platform resolver)",
                        "note": str(e)}), 200


@wb.route("/api/wb/network/rdns", methods=["POST"])
@security.api_login_required
def net_rdns():
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    if not ioc_engine.is_ipv4(ip) and not ioc_engine.is_ipv6(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    recs = network_tools.reverse_dns(ip)
    return jsonify({"ip": ip, "records": recs,
                    "provenance": "OBSERVED" if recs else "UNAVAILABLE",
                    "source": "reverse DNS (OS resolver)"}), 200


# --- file analysis ---

@wb.route("/api/wb/files", methods=["POST"])
@security.api_login_required
def upload_file():
    fh = request.files.get("file")
    if not fh or not fh.filename:
        return jsonify({"error": "No file provided (multipart field 'file')."}), 400
    original = file_analysis.secure_filename_local(fh.filename)
    if not file_analysis.allowed_extension(original):
        return jsonify({"error": f"File type not allowed. Allowed: "
                                 f"{', '.join(sorted(config.ALLOWED_UPLOAD_EXTENSIONS))}"}), 400
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    stored = file_analysis.stored_name_for(original)
    path = os.path.join(config.UPLOAD_DIR, stored)
    written = 0
    with open(path, "wb") as out:
        while True:
            chunk = fh.stream.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > config.MAX_UPLOAD_BYTES:
                out.close()
                os.remove(path)
                return jsonify({"error": f"File exceeds maximum size "
                                         f"({config.MAX_UPLOAD_BYTES} bytes)."}), 413
            out.write(chunk)
    if written == 0:
        os.remove(path)
        return jsonify({"error": "Empty file rejected."}), 400

    analysis = file_analysis.analyze_file(path, original)
    fid = platform_db.save_uploaded_file(stored, original, written, analysis,
                                         kind=analysis["kind"], analyst=security.current_user())
    security.audit_event("file_upload", f"{original} sha256={analysis['sha256']}")
    return jsonify({"file_id": fid, "stored_name": stored, "analysis": analysis}), 200


@wb.route("/api/wb/files", methods=["GET"])
@security.api_login_required
def list_files():
    return jsonify({"files": platform_db.recent_files(limit=100, demo=0)}), 200


@wb.route("/api/wb/files/<int:fid>", methods=["GET"])
@security.api_login_required
def get_file(fid):
    rec = platform_db.get_uploaded_file(fid)
    if not rec:
        return jsonify({"error": "File not found"}), 404
    path = os.path.join(config.UPLOAD_DIR, rec["stored_name"])
    if not os.path.exists(path):
        return jsonify({"record": rec, "analysis": None,
                        "note": "Stored bytes no longer present on disk."}), 200
    return jsonify({"record": rec, "analysis": file_analysis.analyze_file(path, rec["original_name"])}), 200


# --- log analysis ---

@wb.route("/api/wb/logs", methods=["POST"])
@security.api_login_required
def upload_log():
    fh = request.files.get("file")
    if not fh or not fh.filename:
        return jsonify({"error": "No file provided (multipart field 'file')."}), 400
    original = file_analysis.secure_filename_local(fh.filename)
    if os.path.splitext(original)[1].lower() not in (".txt", ".log", ".csv", ".json"):
        return jsonify({"error": "Log uploads must be .txt, .log, .csv or .json"}), 400
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    stored = "log_" + file_analysis.stored_name_for(original)
    path = os.path.join(config.UPLOAD_DIR, stored)
    written = 0
    with open(path, "wb") as out:
        while True:
            chunk = fh.stream.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > config.MAX_LOG_BYTES:
                out.close()
                os.remove(path)
                return jsonify({"error": "Log exceeds maximum size."}), 413
            out.write(chunk)
    summary = log_analysis.analyze(path)
    lid = platform_db.save_log_job(stored, original, written,
                                   summary["overview"]["total_events"], analyst=security.current_user())
    security.audit_event("log_upload", f"{original} events={summary['overview']['total_events']}")
    return jsonify({"log_id": lid, "stored_name": stored, "summary": summary}), 200


@wb.route("/api/wb/logs", methods=["GET"])
@security.api_login_required
def list_logs():
    return jsonify({"logs": platform_db.recent_log_jobs(limit=100, demo=0)}), 200


def _log_path(lid):
    rec = platform_db.get_log_job(lid)
    if not rec:
        return None, None
    return rec, os.path.join(config.UPLOAD_DIR, rec["stored_name"])


@wb.route("/api/wb/logs/<int:lid>/summary", methods=["GET"])
@security.api_login_required
def log_summary(lid):
    rec, path = _log_path(lid)
    if not rec or not os.path.exists(path):
        return jsonify({"error": "Log not found on disk"}), 404
    return jsonify({"record": rec, "summary": log_analysis.analyze(path)}), 200


@wb.route("/api/wb/logs/<int:lid>/search", methods=["POST"])
@security.api_login_required
def log_search(lid):
    rec, path = _log_path(lid)
    if not rec or not os.path.exists(path):
        return jsonify({"error": "Log not found on disk"}), 404
    p = request.get_json(silent=True) or {}
    result = log_analysis.search(
        path,
        keyword=p.get("keyword"),
        regex=p.get("regex"),
        ip=p.get("ip"),
        severity=p.get("severity"),
        event_type=p.get("event_type"),
        start=p.get("start"),
        end=p.get("end"),
        limit=int(p.get("limit", 200)),
    )
    return jsonify(result), 200


# --- cases ---

def _next_case_id() -> str:
    year = datetime.now().year
    existing = platform_db.list_cases(demo=0) + platform_db.list_cases(demo=1)
    nums = []
    for c in existing:
        m = re.match(rf"CASE-{year}-(\d+)$", c["case_id"])
        if m:
            nums.append(int(m.group(1)))
    return f"CASE-{year}-{(max(nums) + 1) if nums else 1:04d}"


@wb.route("/api/wb/cases", methods=["POST"])
@security.api_login_required
def create_case():
    p = request.get_json(silent=True) or {}
    title = (p.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400
    case_id = _next_case_id()
    db_id = platform_db.create_case(case_id, title, p.get("description", ""),
                                    analyst=security.current_user(),
                                    priority=(p.get("priority") or "MEDIUM").upper())
    platform_db.add_timeline(db_id, "case", f"Case {case_id} created", "USER-PROVIDED", "analyst")
    security.audit_event("case_create", case_id)
    return jsonify({"case_id": case_id, "db_id": db_id}), 200


@wb.route("/api/wb/cases", methods=["GET"])
@security.api_login_required
def list_cases():
    return jsonify({"cases": platform_db.list_cases(demo=0)}), 200


@wb.route("/api/wb/cases/<int:db_id>", methods=["GET"])
@security.api_login_required
def get_case(db_id):
    case = platform_db.get_case(db_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({
        "case": case,
        "items": platform_db.case_items(db_id),
        "notes": platform_db.case_notes(db_id),
        "timeline": platform_db.case_timeline(db_id),
    }), 200


@wb.route("/api/wb/cases/<int:db_id>/items", methods=["POST"])
@security.api_login_required
def add_item(db_id):
    if not platform_db.get_case(db_id):
        return jsonify({"error": "Case not found"}), 404
    p = request.get_json(silent=True) or {}
    item_type = (p.get("item_type") or "").strip()
    item_ref = (p.get("item_ref") or "").strip()
    if not item_type or not item_ref:
        return jsonify({"error": "item_type and item_ref are required"}), 400
    platform_db.add_case_item(db_id, item_type, item_ref,
                              label=p.get("label", item_ref),
                              provenance=p.get("provenance", "USER-PROVIDED"),
                              added_by=security.current_user())
    platform_db.add_timeline(db_id, "evidence", f"Attached {item_type}: {item_ref}",
                             p.get("provenance", "USER-PROVIDED"), "analyst")
    security.audit_event("case_attach", f"case={db_id} {item_type}:{item_ref}")
    return jsonify({"added": True}), 200


@wb.route("/api/wb/cases/<int:db_id>/notes", methods=["POST"])
@security.api_login_required
def add_note(db_id):
    if not platform_db.get_case(db_id):
        return jsonify({"error": "Case not found"}), 404
    p = request.get_json(silent=True) or {}
    body = (p.get("body") or "").strip()
    if not body:
        return jsonify({"error": "body is required"}), 400
    platform_db.add_case_note(db_id, security.current_user(), body)
    platform_db.add_timeline(db_id, "note", "Analyst added note", "USER-PROVIDED", "analyst")
    security.audit_event("case_note", f"case={db_id}")
    return jsonify({"added": True}), 200


@wb.route("/api/wb/cases/<int:db_id>/status", methods=["POST"])
@security.api_login_required
def set_case_status(db_id):
    if not platform_db.get_case(db_id):
        return jsonify({"error": "Case not found"}), 404
    p = request.get_json(silent=True) or {}
    status = (p.get("status") or "").upper()
    if status not in ("OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"):
        return jsonify({"error": "status must be OPEN|IN_PROGRESS|RESOLVED|CLOSED"}), 400
    platform_db.update_case(db_id, status=status)
    platform_db.add_timeline(db_id, "case", f"Case status set to {status}", "USER-PROVIDED", "analyst")
    return jsonify({"status": status}), 200


@wb.route("/api/wb/cases/<int:db_id>/timeline", methods=["GET"])
@security.api_login_required
def case_timeline(db_id):
    return jsonify({"timeline": platform_db.case_timeline(db_id)}), 200


# --- reports ---

@wb.route("/api/wb/cases/<int:db_id>/report", methods=["POST"])
@security.api_login_required
def case_report(db_id):
    p = request.get_json(silent=True) or {}
    fmt = (p.get("format") or "pdf").lower()
    out = reports.generate(db_id, fmt, analyst=security.current_user())
    if "error" in out:
        return jsonify({"error": out["error"]}), 404
    platform_db.add_timeline(db_id, "report", f"Generated {fmt.upper()} report {out['stored_name']}",
                             "CALCULATED", "report generator")
    security.audit_event("report_generate", f"case={db_id} fmt={fmt} file={out['stored_name']}")
    return jsonify({"stored_name": out["stored_name"], "format": out["format"],
                    "download_url": f"/api/wb/reports/download/{out['stored_name']}"}), 200


@wb.route("/api/wb/reports", methods=["GET"])
@security.api_login_required
def list_reports():
    return jsonify({"reports": platform_db.recent_reports(limit=100)}), 200


@wb.route("/api/wb/reports/download/<path:stored_name>", methods=["GET"])
@security.api_login_required
def download_report(stored_name):
    safe = os.path.basename(stored_name)
    path = os.path.join(config.REPORT_DIR, safe)
    if not os.path.exists(path):
        return jsonify({"error": "Report not found"}), 404
    security.audit_event("report_download", safe)
    return send_from_directory(config.REPORT_DIR, safe, as_attachment=True)


# --- providers / demo / audit ---

@wb.route("/api/wb/providers", methods=["GET"])
@security.api_login_required
def provider_status():
    return jsonify({"providers": providers.provider_statuses()}), 200


@wb.route("/api/wb/demo", methods=["GET"])
@security.api_login_required
def demo_bundle():
    return jsonify(demo_data.demo_bundle()), 200


@wb.route("/api/wb/demo/seed", methods=["POST"])
@security.api_login_required
def demo_seed():
    out = demo_data.seed_demo()
    security.audit_event("demo_seed", str(out))
    return jsonify(out), 200


@wb.route("/api/wb/demo/cases", methods=["GET"])
@security.api_login_required
def demo_cases():
    return jsonify({"cases": platform_db.list_cases(demo=1)}), 200


@wb.route("/api/wb/audit", methods=["GET"])
@security.api_login_required
def audit_view():
    return jsonify({"audit": platform_db.recent_audit(limit=200)}), 200
