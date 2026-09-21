"""Tests for the Cybersecurity Analyst Workbench.

Covers: input validation/type detection, IOC extraction, encoding/decoding,
log parsing + streaming search, provider honesty (missing keys / failures),
report generation (PDF/JSON/CSV), authentication & authorization, and file
upload security. No fake production results are asserted.
"""
import base64
import io
import json
import os

import pytest

from Backend.app import app
from Backend import config, platform_db, reports, log_analysis, ioc_engine, encoding_tools
from Backend.providers import geoip


@pytest.fixture()
def client(monkeypatch):
    # Keep tests offline and fast: disable the key-free geolocation provider and
    # point storage at temp dirs so real uploads/reports are isolated.
    monkeypatch.setattr(geoip, "GEOIP_ENABLED", False)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _login(client, username=None, password=None):
    return client.post("/api/wb/login", json={
        "username": username or config.ADMIN_USERNAME,
        "password": password or config.ADMIN_PASSWORD,
    }, headers={"Accept": "application/json"})


# --- type detection / validation ---

def test_detect_types():
    assert ioc_engine.detect_type("8.8.8.8") == "IPv4"
    assert ioc_engine.detect_type("2001:db8::1") == "IPv6"
    assert ioc_engine.detect_type("https://example.com/x") == "URL"
    assert ioc_engine.detect_type("example.com") == "DOMAIN"
    assert ioc_engine.detect_type("d41d8cd98f00b204e9800998ecf8427e") == "MD5"
    assert ioc_engine.detect_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "SHA1"
    assert ioc_engine.detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "SHA256"
    assert ioc_engine.detect_type("not-an-indicator !!") == "UNKNOWN"


def test_invalid_ip_rejected_by_analyzer():
    from Backend import analysis_ip
    res = analysis_ip.analyze("999.1.1.1")
    assert res["basic"]["valid"]["value"] is False


# --- IOC extraction ---

def test_ioc_extraction_counts_and_dedup():
    text = ("192.168.1.10 hit 192.168.1.10 and 192.168.1.10 plus 10.0.0.1 "
            "see https://evil.example.com/a and evil.example.com "
            "hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
            "cve CVE-2024-1234 mail admin@example.com")
    ex = ioc_engine.extract_iocs(text)
    ipv4 = {e["value"]: e["occurrences"] for e in ex["ipv4"]}
    assert ipv4["192.168.1.10"] == 3
    assert ipv4["10.0.0.1"] == 1
    assert any(e["value"] == "https://evil.example.com/a" for e in ex["url"])
    # bare domain not double-counted from the URL host
    assert all(e["value"] != "evil.example.com" for e in ex["domain"])
    assert ex["sha256"][0]["value"].startswith("e3b0c442")
    assert ex["cve"][0]["value"] == "CVE-2024-1234"
    assert ex["email"][0]["value"] == "admin@example.com"


# --- encoding / decoding ---

def test_base64_roundtrip():
    enc = encoding_tools.run("encode", "base64", "hello world")
    assert enc["operation"] == "ENCODE"
    dec = encoding_tools.run("decode", "base64", enc["output"])
    assert dec["output"] == "hello world"
    assert dec["provenance"] == "CALCULATED"


def test_decode_not_labelled_malicious():
    dec = encoding_tools.run("decode", "base64", base64.b64encode(b"cmd /c whoami").decode())
    assert "malicious" not in json.dumps(dec).lower()
    assert dec["decoded_shape"]  # descriptive shape only


def test_jwt_decode():
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    token = f"{b64({'alg':'HS256','typ':'JWT'})}.{b64({'sub':'1234','role':'admin'})}.sig"
    out = encoding_tools.run("decode", "jwt", token)
    assert out["output"]["payload"]["role"] == "admin"
    assert any("NOT verified" in n for n in out["notes"])


def test_invalid_codec_rejected():
    with pytest.raises(encoding_tools.CodecError):
        encoding_tools.run("decode", "nope", "x")


# --- log parsing / streaming ---

SAMPLE = "\n".join([
    "2026-09-20T10:00:01 10.0.0.5 user=alice GET / HTTP/1.1\" 200",
    "2026-09-20T10:00:02 10.0.0.9 user=bob POST /login HTTP/1.1\" 401 failed password for bob",
    "2026-09-20T10:00:03 10.0.0.9 user=bob POST /login HTTP/1.1\" 401 failed password for bob",
    "2026-09-20T10:00:04 10.0.0.9 - GET /admin HTTP/1.1\" 404 error",
    "",
])


def test_log_overview_and_stats(tmp_path):
    p = tmp_path / "t.log"
    p.write_text(SAMPLE, encoding="utf-8")
    s = log_analysis.analyze(str(p))
    ov = s["overview"]
    assert ov["total_events"] == 4
    assert ov["authentication_failures"] == 2
    assert ov["errors"] >= 1
    assert ov["unique_source_ips"] == 2
    assert ov["provenance"] == "CALCULATED"
    stats = s["statistics"]
    assert stats["top_source_ips"][0][0] == "10.0.0.9"
    assert stats["http_status_codes"]


def test_log_search_filters(tmp_path):
    p = tmp_path / "t.log"
    p.write_text(SAMPLE, encoding="utf-8")
    r = log_analysis.search(str(p), keyword="failed")
    assert len(r["matches"]) == 2
    r2 = log_analysis.search(str(p), severity="ERROR")
    assert all(m["severity"] == "ERROR" for m in r2["matches"])
    r3 = log_analysis.search(str(p), regex=r"10\.0\.0\.\d")
    assert len(r3["matches"]) == 4
    bad = log_analysis.search(str(p), regex="([unclosed")
    assert "error" in bad


# --- provider honesty ---

def test_providers_not_configured(client):
    _login(client)
    rv = client.get("/api/wb/providers")
    data = rv.get_json()
    for p in data["providers"]:
        assert p["status"] == "NOT CONFIGURED"


def test_investigate_ip_no_fabrication(client, monkeypatch):
    _login(client)
    rv = client.post("/api/wb/investigate", json={"value": "8.8.8.8"})
    assert rv.status_code == 200
    res = rv.get_json()["result"]
    assert res["basic"]["valid"]["value"] is True
    assert res["basic"]["scope"]["provenance"] == "CALCULATED"
    # No configured providers => every TI result must be NOT CONFIGURED, never fake data.
    for ti in res["threat_intelligence"]:
        assert ti["status"] == "NOT CONFIGURED"
        assert ti["data"] == {}
    assert res["ports"]["mode"] == "PASSIVE INTELLIGENCE ONLY"
    assert res["ports"]["open_ports"] == []


def test_investigate_unknown_rejected(client):
    _login(client)
    rv = client.post("/api/wb/investigate", json={"value": "hello there"})
    assert rv.status_code == 400


# --- authentication / authorization ---

def test_workbench_requires_auth(client):
    rv = client.get("/api/wb/dashboard")
    assert rv.status_code == 401
    rv = client.post("/api/wb/cases", json={"title": "x"})
    assert rv.status_code == 401


def test_login_wrong_password(client):
    rv = _login(client, password="wrong-password")
    assert rv.status_code == 401
    rv = client.get("/api/wb/dashboard")
    assert rv.status_code == 401


def test_login_success_and_logout(client):
    rv = _login(client)
    assert rv.status_code == 200
    rv = client.get("/api/wb/dashboard")
    assert rv.status_code == 200
    rv = client.post("/api/wb/logout")
    assert rv.status_code == 200
    rv = client.get("/api/wb/dashboard")
    assert rv.status_code == 401


# --- file upload security ---

def test_upload_disallowed_extension(client):
    _login(client)
    rv = client.post("/api/wb/files", data={
        "file": (io.BytesIO(b"hello"), "notes.md")}, content_type="multipart/form-data")
    assert rv.status_code == 400


def test_upload_path_traversal_neutralized(client):
    _login(client)
    rv = client.post("/api/wb/files", data={
        "file": (io.BytesIO(b"MZ\x90\x00"), "../../etc/evil.md")}, content_type="multipart/form-data")
    assert rv.status_code == 400  # .md not allowed even after basename sanitization


def test_upload_size_limit(client, monkeypatch):
    _login(client)
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 8)
    rv = client.post("/api/wb/files", data={
        "file": (io.BytesIO(b"MZ" + b"\x00" * 64), "big.exe")}, content_type="multipart/form-data")
    assert rv.status_code == 413


def test_upload_pe_analyzed_locally(client):
    _login(client)
    # minimal MZ header so detect_kind == PE; structure parse will report an error
    # gracefully rather than fabricating sections.
    blob = b"MZ" + b"\x00" * 200
    rv = client.post("/api/wb/files", data={
        "file": (io.BytesIO(blob), "sample.exe")}, content_type="multipart/form-data")
    assert rv.status_code == 200
    a = rv.get_json()["analysis"]
    assert a["kind"] == "PE"
    assert a["hash_provenance"] == "CALCULATED"
    assert len(a["sha256"]) == 64
    assert "NOT PERFORMED" in a["external_submission"]


# --- cases + reports ---

def test_case_workflow_and_pdf_report(client):
    _login(client)
    rv = client.post("/api/wb/cases", json={"title": "Test case", "description": "scope"})
    assert rv.status_code == 200
    db_id = rv.get_json()["db_id"]
    case_id = rv.get_json()["case_id"]
    assert case_id.startswith("CASE-")

    rv = client.post(f"/api/wb/cases/{db_id}/items", json={
        "item_type": "ip", "item_ref": "203.0.113.5", "provenance": "OBSERVED"})
    assert rv.status_code == 200
    rv = client.post(f"/api/wb/cases/{db_id}/notes", json={"body": "analyst interpretation"})
    assert rv.status_code == 200

    rv = client.post(f"/api/wb/cases/{db_id}/report", json={"format": "pdf"})
    assert rv.status_code == 200
    stored = rv.get_json()["stored_name"]
    path = os.path.join(config.REPORT_DIR, stored)
    with open(path, "rb") as fh:
        blob = fh.read()
    assert blob.startswith(b"%PDF")
    assert blob.rstrip().endswith(b"%%EOF")

    rv = client.post(f"/api/wb/cases/{db_id}/report", json={"format": "json"})
    assert rv.status_code == 200
    rv = client.post(f"/api/wb/cases/{db_id}/report", json={"format": "csv"})
    assert rv.status_code == 200

    rv = client.get(f"/api/wb/cases/{db_id}/timeline")
    kinds = [e["kind"] for e in rv.get_json()["timeline"]]
    assert "case" in kinds and "evidence" in kinds and "note" in kinds and "report" in kinds


def test_report_download_traversal_blocked(client):
    _login(client)
    rv = client.get("/api/wb/reports/download/..%2F..%2Fetc%2Fpasswd")
    assert rv.status_code in (400, 404)


# --- demo isolation ---

def test_demo_records_isolated(client):
    _login(client)
    real = client.get("/api/wb/cases").get_json()["cases"]
    demo = client.get("/api/wb/demo/cases").get_json()["cases"]
    assert all(c["demo"] == 0 for c in real)
    assert all(c["demo"] == 1 for c in demo)
    bundle = client.get("/api/wb/demo").get_json()
    assert bundle["label"] == "DEMO DATA"
