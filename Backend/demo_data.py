"""Bundled demonstration data, strictly labeled DEMO DATA.

Demo records are persisted with demo=1 and are only surfaced in the Demo view;
they are never mixed with real investigations, alerts or metrics. Nothing here
is presented as a real observation or real threat-intelligence result.
"""
import os

from . import config, platform_db, file_analysis

SAMPLE_LOG = """2026-09-20T10:32:04 192.168.1.20 user=alice GET /login HTTP/1.1" 200
2026-09-20T10:32:08 192.168.1.20 user=alice GET /dashboard HTTP/1.1" 200
2026-09-20T10:33:11 10.10.10.25 user=bob POST /login HTTP/1.1" 401 failed password for bob
2026-09-20T10:33:14 10.10.10.25 user=bob POST /login HTTP/1.1" 401 failed password for bob
2026-09-20T10:33:19 10.10.10.25 user=bob POST /login HTTP/1.1" 401 failed password for bob
2026-09-20T10:34:02 10.10.10.25 user=admin POST /login HTTP/1.1" 401 invalid user admin
2026-09-20T10:35:40 203.0.113.7 - GET /admin HTTP/1.1" 404
2026-09-20T10:36:01 203.0.113.7 - GET /wp-login.php HTTP/1.1" 404
2026-09-20T10:36:55 198.51.100.9 - GET / HTTP/1.1" 200
2026-09-20T10:37:12 198.51.100.9 - GET /assets/app.js HTTP/1.1" 200
2026-09-20T10:40:02 192.168.1.20 user=alice GET /reports HTTP/1.1" 200
2026-09-20T10:41:33 10.10.10.25 - GET /etc/passwd HTTP/1.1" 400 error request
2026-09-20T10:42:10 203.0.113.7 - GET /phpmyadmin/ HTTP/1.1" 404
2026-09-20T10:44:51 192.168.1.20 user=alice POST /upload HTTP/1.1" 200
2026-09-20T10:45:07 10.10.10.25 - GET /?cmd=whoami HTTP/1.1" 400 error request
"""

SAMPLE_IOCS = [
    {"type": "IPv4", "value": "10.10.10.25"},
    {"type": "IPv4", "value": "203.0.113.7"},
    {"type": "DOMAIN", "value": "example-malware.test"},
    {"type": "SHA256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
]

SAMPLE_NIDS_EVENTS = [
    {"ts": "2026-09-20T10:34:51", "kind": "NIDS", "summary": "DEMO PORT_SCAN from 10.10.10.25 (8 unique ports)",
     "provenance": "DEMO DATA"},
    {"ts": "2026-09-20T10:35:02", "kind": "NIDS", "summary": "DEMO SUSPICIOUS_PORT 23 from 10.10.10.25",
     "provenance": "DEMO DATA"},
]


def sample_log_path() -> str:
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    path = os.path.join(config.UPLOAD_DIR, "demo_sample.log")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(SAMPLE_LOG)
    return path


def seed_demo() -> dict:
    """Create/refresh the bundled demo case. Returns a summary dict."""
    if not config.DEMO_ENABLED:
        return {"enabled": False}
    existing = platform_db.get_case_by_code("CASE-DEMO-0001")
    if existing:
        return {"enabled": True, "case_id": "CASE-DEMO-0001", "created": False}

    db_id = platform_db.create_case(
        "CASE-DEMO-0001",
        "DEMO - Suspicious outbound traffic (sample data)",
        "Bundled demonstration case. All contents are DEMO DATA, not real observations.",
        "demo", status="OPEN", priority="LOW", demo=1,
    )
    for ioc in SAMPLE_IOCS:
        platform_db.add_case_item(db_id, "ioc", ioc["value"],
                                  label=f"DEMO {ioc['type']}", provenance="DEMO DATA", added_by="demo")
    for ev in SAMPLE_NIDS_EVENTS:
        platform_db.add_timeline(db_id, ev["kind"], ev["summary"], ev["provenance"], "demo bundle")
    platform_db.add_case_note(db_id, "demo",
                              "This note is DEMO DATA illustrating analyst interpretation.")
    log_path = sample_log_path()
    platform_db.save_log_job(os.path.basename(log_path), "demo_sample.log",
                             os.path.getsize(log_path), SAMPLE_LOG.count("\n"), analyst="demo", demo=1)
    return {"enabled": True, "case_id": "CASE-DEMO-0001", "created": True}


def demo_bundle() -> dict:
    return {
        "label": "DEMO DATA",
        "note": "Everything in this view is bundled sample data for demonstration only. "
                "It is not real traffic, real intelligence, or a real investigation.",
        "sample_log": SAMPLE_LOG,
        "sample_iocs": SAMPLE_IOCS,
        "sample_nids_events": SAMPLE_NIDS_EVENTS,
    }
