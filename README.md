# Cybersecurity Analyst Workbench + Network Intrusion Detection System (NIDS)

A production-oriented **Cybersecurity Analyst Workbench** built on top of a rule-based Network Intrusion Detection System (NIDS). Python Flask, Scapy, SQLite, Socket.IO, a SOC Security Dashboard, and an authenticated analyst workbench for IOC investigation, log/file analysis, case management and professional PDF reporting.

The platform's core principle: **REAL INPUT → REAL PROCESSING → REAL EVIDENCE → TRACEABLE RESULT → PROFESSIONAL REPORT**. No result is ever fabricated. Every value carries a provenance label (`OBSERVED`, `CALCULATED`, `EXTRACTED`, `EXTERNAL INTELLIGENCE`, `INFERRED`, `USER-PROVIDED`, `UNAVAILABLE`), and any source that is missing or failing reports `NOT CONFIGURED` / `TEMPORARILY UNAVAILABLE` / `No result returned by source.` instead of invented data.

> **Disclaimer**: This tool is designed strictly for educational, defensive, and authorized security monitoring purposes. Live network packet capture and testing must only be executed on networks and devices for which you have explicit authorization. The platform performs **passive observation only** — it contains no active port-scanning capability and never scans arbitrary Internet targets.

---

## 🏛️ Architecture Overview

```text
                                  +-------------------+
                                  |  Network Traffic  |
                                  |   (Live / Demo)   |
                                  +---------+---------+
                                            |
                                            v
                                  +---------+---------+
                                  |  Packet Sniffer   | (Scapy / Live + Demo Fallback)
                                  +---------+---------+
                                            |
                                            v
                                  +---------+---------+
                                  |  Packet Analyzer  | (Metadata Normalizer)
                                  +---------+---------+
                                            |
                                            v
                                  +---------+---------+
                                  | Detection Engine  | (Stateful Rules: Port Scan, SYN Flood)
                                  +---------+---------+
                                            |
                                            v
                                  +---------+---------+
                                  |   Alert Engine    | (Structured Event Generator)
                                  +----+--------+-----+
                                       |        |
                         +-------------+        +------------+
                         v                                   v
              +----------+----------+               +--------+--------+
              | SQLite Database DB  |               | Socket.IO Broadcast|
              +---------------------+               +--------+--------+
                                                             |
                                                             v
                                                    +--------+--------+
                                                    |   SOC Dashboard |
                                                    | (Dark Cyber UI) |
                                                    +-----------------+
```

---

## ✨ Features

- **Stateful Detection Engine**:
  - **Port Scan Detection**: Detects when a single source IP probes $\ge 8$ unique destination ports within a configurable 10-second sliding time window.
  - **SYN Flood Detection**: Detects high-frequency TCP SYN flag bursts.
  - **High-Risk Port Inspection**: Triggers alerts for probes targeting sensitive ports (e.g. Telnet 23, Metasploit 4444, IRC Botnet 6667).
- **Windows Live Capture & Demo Fallback**: Automatically attempts live packet capture via Scapy. If WinPcap/Npcap or elevated privileges are missing, seamlessly defaults to DEMO mode without crashing the app.
- **SQLite Database Persistence**: Automatically initializes tables (`alerts`, `traffic_stats`, `packet_logs`) and persists incident history across restarts.
- **Real-Time Websocket Updates**: Emits instant alert notifications and stats updates to connected dashboards via Flask-SocketIO (with automatic HTTP polling fallback).
- **Modern SOC Dashboard**: High-density cybersecurity UI featuring metric cards, Chart.js analytics graphs (timeline, attack types, severity, top attackers), and live alert logs.
- **Cybersecurity Analyst Workbench** (authenticated, `/workbench`):
  - **IOC Investigation Center** — auto-detects IPv4/IPv6/URL/domain/MD5/SHA1/SHA256/SHA512 and runs real analysis (local validation, DNS, RDAP, TLS certificate, geolocation, threat intelligence).
  - **Log Analyzer** — streaming/chunked analysis of TXT/LOG/CSV/JSON with overview, statistics, search (keyword/regex/IP/severity/time) and IOC extraction with occurrence counts.
  - **File Analysis** — local MD5/SHA1/SHA256/SHA512, Shannon entropy, strings, PE/ELF structure; files are never sent externally automatically.
  - **Encoding / Decoding** — Base64, URL, hex, binary, ROT13, HTML entities, unicode, JWT; every operation is explicitly labeled ENCODE or DECODE.
  - **Network Tools** — CIDR math, DNS lookups, reverse DNS; OBSERVED vs CALCULATED never mixed.
  - **Investigation Cases** — attach indicators, files, logs, NIDS alerts, notes; evidence timeline; PDF/JSON/CSV report generation.
  - **Threat-Intelligence Providers** — VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, GeoIP as independent adapters; missing keys report NOT CONFIGURED.
  - **Demo Mode** — bundled sample data, strictly labeled `DEMO DATA`, never mixed with real analysis.

---

## 🚀 Tech Stack

- **Backend**: Python 3.13, Flask, Flask-CORS, Flask-SocketIO, Scapy, SQLite3
- **Frontend**: HTML5, CSS3 (Vanilla Dark SOC Design System), JavaScript (ES6+), Chart.js, Socket.IO Client, FontAwesome 6
- **Testing**: pytest

---

## 📂 Project Structure

```text
NIDS/
│
├── Backend/
│   ├── app.py              # Main Flask REST API & Web Server (legacy NIDS routes)
│   ├── config.py           # Thresholds, server & workbench configuration (env-driven)
│   ├── database.py         # NIDS SQLite Schema & Query Helpers
│   ├── models.py           # Dataclasses (Packet, Alert)
│   ├── analyzer.py         # Packet Normalizer
│   ├── detector.py         # Stateful Intrusion Detection Engine
│   ├── alert_engine.py     # Alert Processor & Persister
│   ├── sniffer.py          # Scapy Sniffer & honest capture-state machine
│   ├── asset_filter.py     # Asset IP / direction filter (BOTH|INBOUND|OUTBOUND)
│   ├── socket_handler.py   # Socket.IO Listener & Broadcaster
│   │
│   ├── security.py         # Auth (PBKDF2), sessions, rate limiting, audit log
│   ├── platform_db.py      # Workbench SQLite schema (users, cases, evidence, reports)
│   ├── workbench_routes.py # /workbench UI + /api/wb/* REST blueprint
│   ├── ioc_engine.py       # Reusable IOC extraction engine (IP/URL/domain/hash/email/CVE)
│   ├── encoding_tools.py   # Encode/decode codecs incl. JWT (signature NOT verified)
│   ├── network_tools.py    # Pure-python DNS client, rDNS, CIDR math, SSRF guard
│   ├── analysis_ip.py      # IP investigation orchestrator
│   ├── analysis_url.py     # URL investigation orchestrator
│   ├── analysis_domain.py  # Domain investigation orchestrator (DNS/RDAP/TLS)
│   ├── analysis_hash.py    # Hash investigation orchestrator
│   ├── analysis_common.py  # Shared provenance/field helpers
│   ├── file_analysis.py    # Local hashing, entropy, strings, PE/ELF parsing
│   ├── log_analysis.py     # Streaming chunked log overview/statistics/search
│   ├── pdf_writer.py       # Dependency-free PDF 1.4 writer
│   ├── reports.py          # Case evidence gathering + PDF/JSON/CSV report builder
│   ├── demo_data.py        # Bundled, strictly-labeled DEMO sample data
│   │
│   └── providers/          # Independent threat-intelligence adapters
│       ├── base.py         # ProviderResult / statuses / http helper
│       ├── virustotal.py   # VirusTotal v3
│       ├── abuseipdb.py    # AbuseIPDB check
│       ├── otx.py          # AlienVault OTX
│       ├── greynoise.py    # GreyNoise noise/context
│       └── geoip.py        # Key-free geolocation (ipwho.is)
│
├── Frontend/
│   ├── index.html          # SOC Security Dashboard HTML (Network Monitoring)
│   ├── workbench.html      # Analyst Workbench SPA shell
│   ├── css/
│   │   └── style.css       # Cybersecurity Dark Theme Styles
│   └── js/
│       ├── dashboard.js    # Dashboard Controller & Chart.js Engine
│       └── workbench.js    # Workbench client (all views)
│
├── tests/
│   ├── test_detector.py    # Unit tests for Port Scan / SYN Flood rules
│   ├── test_detection_quality.py  # Determinism, malformed packets, cooldown tests
│   ├── test_db.py          # Unit tests for SQLite operations
│   ├── test_api.py         # Integration tests for legacy REST API
│   ├── test_asset_monitoring.py  # Asset filter / capture-state / monitor API
│   └── test_workbench.py   # Workbench: IOC, encode, logs, files, cases, reports, auth
│
├── requirements.txt        # Python Dependencies
├── .env.example            # Environment variables template
├── Dockerfile              # Container image (python:3.11-slim)
├── docker-compose.yml      # Host-network capture deployment
└── README.md               # Complete Project Documentation
```

---

## 🛠️ Quick Start & Installation

### 1. Create & Activate Virtual Environment

```powershell
python -m venv venv
.\venv\Scripts\activate
```

### 2. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 3. Run the NIDS Server

```powershell
python -m Backend.app
```

The server will start on: `http://127.0.0.1:5000`

### 4. Access the SOC Dashboard

Open your web browser and navigate to:
```text
http://127.0.0.1:5000          # Network Monitoring (NIDS) dashboard
http://127.0.0.1:5000/workbench   # Cybersecurity Analyst Workbench (login required)
```

Default workbench credentials (override via `ANALYST_USERNAME` / `ANALYST_PASSWORD`):
```text
username: analyst
password: changeme-in-production
```

### 5. (Optional) Run with Docker

```powershell
docker compose up --build
```

The compose file uses host networking plus `NET_RAW`/`NET_ADMIN` so Scapy can capture, and persists the database, uploads and reports on a named volume. See [Deployment](#-deployment) below.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | System health check and sniffer status |
| `GET` | `/api/status` | Current sniffer mode (`LIVE` vs `DEMO`) |
| `GET` | `/api/stats` | Aggregated threat counts, packets & detection rate |
| `GET` | `/api/alerts` | Retrieve recent alerts (supports `?limit=`, `?severity=`) |
| `GET` | `/api/alerts/<id>` | Retrieve a single alert by id |
| `GET` | `/api/attacks` | Attack statistics and category breakdown |
| `GET` | `/api/threats` | Active unresolved security threats |
| `GET` | `/api/detections` | Active rule definitions and recent detections |
| `POST` | `/api/monitor/start` | Start asset-scoped monitoring (`{"asset_ip","mode"}`) |
| `POST` | `/api/monitor/stop` | Stop asset-scoped monitoring (capture keeps running) |
| `GET` | `/api/monitor/status` | Asset filter, capture state, packets/flows observed |
| `POST` | `/api/alerts/<id>/resolve` | Mark an alert `RESOLVED` |
| `POST` | `/api/demo/attack` | Trigger controlled simulated attack (`PORT_SCAN` or `SYN_FLOOD`) |
| `POST` | `/api/clear` | Clear all persisted database alerts and reset metrics |

### Analyst Workbench API (`/api/wb/*`, session-authenticated)

All workbench endpoints require a logged-in session (`POST /api/wb/login`). Unauthenticated calls return `401`. Results always include provenance labels.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/wb/login` | Authenticate (`{"username","password"}`); 401 on bad credentials |
| `POST` | `/api/wb/logout` | End the session |
| `GET` | `/api/wb/session` | Current session state |
| `GET` | `/api/wb/dashboard` | Real dashboard metrics (cases, investigations, reports, NIDS alerts, providers, audit) |
| `POST` | `/api/wb/investigate` | Auto-detect type and run real analysis (`{"value"}`); 400 if unknown |
| `GET` | `/api/wb/investigations` | Recent investigations |
| `GET` | `/api/wb/investigation/<id>` | One stored investigation result |
| `POST` | `/api/wb/ioc/extract` | Extract IOCs with occurrence counts (`{"text","source"}`) |
| `POST` | `/api/wb/encode` | Encode/decode (`{"operation","codec","data"}`) |
| `POST` | `/api/wb/network/cidr` | CIDR analysis (`{"cidr"}`) |
| `POST` | `/api/wb/network/dns` | DNS lookup (`{"name","qtype"}`) |
| `POST` | `/api/wb/network/rdns` | Reverse DNS (`{"ip"}`) |
| `POST` | `/api/wb/files` | Upload + local file analysis (multipart `file`); 413 over size cap |
| `GET` | `/api/wb/files` / `/api/wb/files/<id>` | List / fetch uploaded-file analyses |
| `POST` | `/api/wb/logs` | Upload + streaming log analysis (multipart `file`) |
| `GET` | `/api/wb/logs` / `/api/wb/logs/<id>/summary` | List / fetch log overview+statistics+IOCs |
| `POST` | `/api/wb/logs/<id>/search` | Re-stream search (`keyword`,`regex`,`ip`,`severity`,`event_type`,`start`,`end`,`limit`) |
| `POST` | `/api/wb/cases` | Create a case (`{"title","description","priority"}`) |
| `GET` | `/api/wb/cases` / `/api/wb/cases/<id>` | List / fetch cases (demo cases excluded from real list) |
| `POST` | `/api/wb/cases/<id>/items` | Attach evidence (`{"item_type","item_ref","label","provenance"}`) |
| `POST` | `/api/wb/cases/<id>/notes` | Add analyst note (`{"body"}`) |
| `POST` | `/api/wb/cases/<id>/status` | Change case status (`{"status"}`) |
| `GET` | `/api/wb/cases/<id>/timeline` | Evidence timeline |
| `POST` | `/api/wb/cases/<id>/report` | Generate report (`{"format":"pdf"|"json"|"csv"}`) |
| `GET` | `/api/wb/reports` | List generated reports |
| `GET` | `/api/wb/reports/download/<name>` | Download a report (basename-sanitized) |
| `GET` | `/api/wb/providers` | Provider configuration status |
| `GET`/`POST` | `/api/wb/demo` | Fetch / seed strictly-labeled demo bundle |
| `GET` | `/api/wb/demo/cases` | Demo-only case list |
| `GET` | `/api/wb/audit` | Audit log of analyst actions |

---

## 🧪 Running Automated Tests

Execute the complete pytest test suite:

```powershell
.\venv\Scripts\python.exe -m pytest tests/ -v
```

All 73 unit and integration tests cover detection thresholds, asset filtering, capture-state transitions, database transactions, legacy API endpoints, and the full workbench (IOC detection, IOC extraction, encoding, log parsing/search, file-upload security, provider NOT-CONFIGURED behaviour, authentication, case workflow and PDF/JSON/CSV report generation).

---

## 🎯 Asset IP Monitoring — Data Flow & Documentation

Real-time monitoring of a user-specified asset IP. Only packets that are **actually captured** on the wire are analyzed; nothing is simulated, randomized, or hard-coded in this path.

```text
PACKET CAPTURE SOURCE      Backend/sniffer.py   NetworkSniffer._sniff_loop (Scapy sniff)
        ↓
IP EXTRACTION              Backend/analyzer.py  PacketAnalyzer.parse_scapy_packet
        ↓
ASSET FILTER               Backend/asset_filter.py  AssetFilter.matches / .direction
        ↓
DETECTION ENGINE           Backend/detector.py  IntrusionDetector.analyze_packet
        ↓
ALERT CREATION             Backend/alert_engine.py  process_alert -> Backend/database.py save_alert
        ↓
API / WEBSOCKET            Backend/app.py       /api/* + socketio.emit("new_alert"/"monitor_status")
        ↓
DASHBOARD                  Frontend/js/dashboard.js  renderAlertsTable / renderMonitorStatus
```

### 1. Where packets enter the system
`Backend/sniffer.py` — `NetworkSniffer._sniff_loop()` runs Scapy `sniff()` in a daemon thread against the resolved capture interface. Every raw frame is handed to `_handle_scapy_packet()`. The legacy `trigger_demo_*` methods are an **explicitly separate, labeled simulation path** used only by the `[ Simulate ]` panel; they never update capture liveness and are marked `"simulated": true`.

### 2. Which component extracts source/destination IPs
`Backend/analyzer.py` — `PacketAnalyzer.parse_scapy_packet()` reads the `IP` layer (`src`/`dst`), the `TCP`/`UDP` layer ports, `ICMP`/`ARP` handling, the packet length, TCP `flags`, and the capture interface (`sniffed_on`). It returns a normalized `Packet` dataclass (`Backend/models.py`). Values are read from the frame; they are never invented.

### 3. How the asset IP filter works
`Backend/asset_filter.py` — `AssetFilter(asset_ip, mode)`. The asset IP is strictly validated as an IPv4 address (`ipaddress.IPv4Address`); an invalid value raises and the API rejects it with HTTP 400. Modes: `BOTH` (default; source **or** destination equals the asset), `INBOUND` (destination equals the asset), `OUTBOUND` (source equals the asset). When no asset is configured the filter is disabled and all captured packets pass through. The filter is applied **before** any asset-scoped detection or flow accounting, so non-matching packets never reach the detector or the asset counters.

### 4. Where detection rules execute
`Backend/detector.py` — `IntrusionDetector.analyze_packet()`. Three deterministic, stateful rules run in order: `PORT_SCAN` (≥ `PORT_SCAN_THRESHOLD` unique destination ports from one `(src,dst)` pair inside `PORT_SCAN_WINDOW`), `SYN_FLOOD` (≥ `SYN_FLOOD_THRESHOLD` genuine connection-open SYNs — SYN set, ACK clear — from one source inside `SYN_FLOOD_WINDOW`, optionally gated by `SYN_FLOOD_RATE_THRESHOLD`), and `SUSPICIOUS_PORT` (destination port present in the configurable `SUSPICIOUS_PORTS` map). All thresholds are environment-configurable in `Backend/config.py`. A per-key cooldown (`ALERT_COOLDOWN`) prevents one ongoing event from emitting duplicate alerts.

### 5. Where alerts are created
`Backend/alert_engine.py` — `process_alert()` assigns an id/timestamp and forwards to `Backend/database.py` `save_alert()`, which persists the alert (including `asset_ip`, a JSON `evidence` object, and `first_seen`/`last_seen`) to SQLite. Evidence fields are computed from the packets that actually triggered the rule (e.g. `unique_ports`, `ports`, `packet_count`, `window_seconds`, `threshold`, `observed_rate_per_sec`); no field is fabricated.

### 6. How alerts reach the dashboard
`Backend/alert_engine.py` emits `socketio.emit("new_alert", ...)` on creation; `Backend/app.py` also exposes `GET /api/alerts`. `Frontend/js/dashboard.js` consumes the WebSocket event (`onNewAlertReceived`) for instant rows and re-polls `/api/stats` so metric cards and charts stay consistent with the database.

### 7. How metrics are calculated
`Backend/database.py` `get_stats()` derives every number from persisted rows and live sniffer counters — nothing is hard-coded. `total_packets`/`total_bytes` come from batched sniffer counter flushes; `flows_observed`/`flows_active` from the sniffer's 5-tuple flow table; `detections`/`total_alerts` from `COUNT(*)` on alerts; `active_alerts`/`active_threats` from alerts inside `ACTIVE_THREAT_WINDOW` **and** `status='ACTIVE'`; `resolved_alerts` from `status='RESOLVED'`; `historical_alerts` from alerts older than the active window; `detection_rate = total_alerts / total_packets`. The dashboard's "OBSERVED EVENTS ONLY" badge states that no external threat-intelligence enrichment is connected.

### 8. How to start real-time monitoring
Open the dashboard, enter an asset IP in **Asset IP**, choose **Monitoring** (`BOTH`/`INBOUND`/`OUTBOUND`), and press **START MONITORING** (or `POST /api/monitor/start`). The panel then shows Monitored Asset, Capture Interface, Capture Status, Asset Packets and Flows, refreshed by polling `/api/monitor/status`. The top badge reads **LIVE MONITORING** only while capture is verified-live *and* an asset is scoped; with capture live but no asset it reads **CAPTURE LIVE**; otherwise it shows the raw honest state (`NO_TRAFFIC`, `CAPTURE_ERROR`, `PERMISSION_DENIED`, `NO_INTERFACE`, `DISCONNECTED`, `STOPPED`).

### 9. How to select the capture interface
The interface is resolved at startup in `NetworkSniffer._resolve_interface()`: the `DEFAULT_INTERFACE` setting (env `NIDS_INTERFACE`) if set, otherwise Scapy's `conf.iface`, otherwise the first entry of `get_if_list()`. The resolved name is reported in `/api/monitor/status` and on the dashboard. On Windows, live capture additionally requires Npcap and (typically) an elevated terminal.

### 10. How to test the system safely
Only generate traffic on networks you are authorized to test (e.g. an isolated host-only/lab adapter). A safe procedure: run the app; confirm the resolved interface in `/api/monitor/status`; start monitoring a lab asset IP; emit or produce legitimate lab traffic toward that asset (e.g. Scapy `sendp` of TCP SYNs on a host-only adapter, or connections to your own lab hosts); confirm `packets_observed`/`asset_packets_observed` rise and that `PORT_SCAN`/`SYN_FLOOD`/`SUSPICIOUS_PORT` alerts carry the asset IP and evidence; confirm the dashboard updates; then press **STOP** and confirm the badge leaves `LIVE MONITORING`. Never point the tool at arbitrary Internet targets — NIDS performs passive observation only and contains no active scanning capability. The automated suite (`tests/`) exercises the same pipeline deterministically without touching the network.

---

## 🧰 Cybersecurity Analyst Workbench — Documentation

### 1. What the platform does
The workbench brings common analyst investigation tasks into one authenticated application: IOC investigation (IP/URL/domain/hash), log analysis, file analysis, IOC extraction, encoding/decoding, network calculations, threat-intelligence lookups, investigation cases with an evidence timeline, and professional PDF/JSON/CSV reporting. The existing NIDS remains available as **Network Monitoring** (the `/` dashboard) and is linked from the workbench top bar. The standard is real input → real processing → real evidence → traceable result → professional report.

### 2. Architecture
```text
LOGIN (security.py, PBKDF2 + signed session cookie)
   ↓
WORKBENCH BLUEPRINT (workbench_routes.py)  — rate-limited, session-gated /api/wb/*
   ↓
ANALYZERS (analysis_ip/url/domain/hash.py) — orchestrate local + external sources
   ├── ioc_engine.py        IOC extraction (regex, dedup, occurrence counts)
   ├── network_tools.py     pure-python DNS, rDNS, CIDR, SSRF guard
   ├── encoding_tools.py    encode/decode codecs
   ├── file_analysis.py     local hashes, entropy, strings, PE/ELF
   ├── log_analysis.py      streaming chunked log analysis
   └── providers/*          VirusTotal / AbuseIPDB / OTX / GreyNoise / GeoIP adapters
   ↓
platform_db.py (SQLite: users, audit_log, cases, case_items, case_notes,
                timeline_events, investigations, uploaded_files, log_jobs, reports)
   ↓
reports.py + pdf_writer.py  →  PDF / JSON / CSV artifacts in REPORT_DIR
```
The NIDS pipeline (sniffer → analyzer → asset_filter → detector → alert_engine → database → socket/dashboard) is unchanged and remains the source of all Network Monitoring metrics.

### 3. Installation
See [Quick Start](#-quick-start--installation). In short: create a venv, `pip install -r requirements.txt`, `python -m Backend.app`. No system packages are required on Linux (Scapy uses AF_PACKET); on Windows install Npcap and run elevated for live capture.

### 4. Configuration
All configuration is environment-driven (see `.env.example`). Key groups: server (`HOST`, `PORT`, `FLASK_DEBUG`, `SECRET_KEY`), detection thresholds (`PORT_SCAN_*`, `SYN_FLOOD_*`, `ALERT_COOLDOWN`, `SUSPICIOUS_PORTS`), capture (`DEFAULT_INTERFACE`, `ASSET_IP`, `ASSET_MODE`, `CAPTURE_LIVENESS_SECONDS`), workbench auth (`ANALYST_USERNAME`, `ANALYST_PASSWORD`, `SESSION_LIFETIME_SECONDS`, `RATE_LIMIT_*`), uploads/reports (`UPLOAD_DIRNAME`, `REPORT_DIRNAME`, `MAX_UPLOAD_BYTES`, `MAX_LOG_BYTES`, `REPORT_CLASSIFICATION`), providers (`*_API_KEY`, `GEOIP_ENABLED`, `PROVIDER_TIMEOUT`), and `DEMO_ENABLED`.

### 5. API keys
Provider keys are read **only** from environment variables (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`). They are never hard-coded, never logged, and never sent to the frontend. A provider with an empty key reports `NOT CONFIGURED` and is skipped without a network call; the platform remains fully usable for local analysis.

### 6. Threat-intelligence providers
Independent adapters under `Backend/providers/`. Each returns a `ProviderResult` with `provider`, `status` (`OK` / `NOT CONFIGURED` / `TEMPORARILY UNAVAILABLE` / `NO RESULT` / `UNSUPPORTED INDICATOR TYPE`), `data` (only what the provider actually returned), `reason`, `retrieved_at`, and `provenance` (`EXTERNAL INTELLIGENCE` only when `OK`, otherwise `UNAVAILABLE`). HTTP 404 maps to `NO RESULT`; timeouts/other errors map to `TEMPORARILY UNAVAILABLE`. GeoIP (ipwho.is) is key-free and can be disabled with `GEOIP_ENABLED=False`.

### 7. IOC investigation
`POST /api/wb/investigate {"value": ...}` auto-detects the type (IPv4/IPv6/URL/domain/MD5/SHA1/SHA256/SHA512) and dispatches to the matching analyzer. IP results include local validation (CALCULATED), reverse DNS (OBSERVED), geolocation (EXTERNAL INTELLIGENCE when configured), threat intelligence per provider, and a ports block that is always `PASSIVE INTELLIGENCE ONLY` with an empty `open_ports` list (no active scanning exists). Domain results include DNS A/AAAA/MX/NS/TXT/CNAME (OBSERVED via the platform resolver), RDAP registration (EXTERNAL INTELLIGENCE), and the TLS certificate (OBSERVED). URL results parse the URL (EXTRACTED), resolve the host (OBSERVED) and query intelligence for the URL, domain and resolved IPs. Hash results identify the type (CALCULATED) and query file intelligence. Unknown input returns HTTP 400.

### 8. Log analysis
Upload TXT/LOG/CSV/JSON via `POST /api/wb/logs`. Files are read in 1 MiB chunks (`LOG_STREAM_CHUNK`) in a single pass — large logs never load wholly into memory. The overview reports total events, time range, event rate, unique IPs/users/domains/URLs, errors and authentication failures. Statistics report top source/destination IPs, domains, URLs, users, HTTP status codes and event types. Search re-streams the file with line numbers and supports keyword, regex (invalid regex returns an error, not a crash), IP, severity, event type and time-range filters. IOCs are extracted with occurrence counts and can be pivoted into investigations.

### 9. File analysis
Upload via `POST /api/wb/files`. The platform computes MD5/SHA1/SHA256/SHA512 locally (streaming), Shannon entropy, printable strings, and — for executables — PE or ELF structure (machine, sections, imports) by parsing headers directly. Provenance is `CALCULATED`. **Files are never uploaded to external services automatically**; the result states `external_submission: NOT PERFORMED (requires explicit analyst action)`. Uploads are size-capped (413), extension-allowlisted, and stored under UUID names with sanitized basenames (path-traversal safe).

### 10. NIDS (Network Monitoring)
The legacy NIDS is preserved unchanged and integrated as the **Network Monitoring** module. See [Asset IP Monitoring](#-asset-ip-monitoring--data-flow--documentation) for its data flow, honest capture states, and detection rules. NIDS alerts can be attached to workbench cases as evidence (`item_type: "alert"`).

### 11. Case management
`POST /api/wb/cases` creates a case (`CASE-<year>-NNNN`) with title, description, analyst, status and priority. Evidence of any kind (ip/url/domain/hash/ioc/alert/file/log/investigation) is attached via `/items`; analyst notes via `/notes`; status changes via `/status`. Every mutation appends a `timeline_events` row so the full investigation history is reconstructable. `GET /api/wb/cases/<id>` returns items, notes and metadata; `/timeline` returns the chronological evidence trail.

### 12. PDF reporting
`POST /api/wb/cases/<id>/report {"format":"pdf"|"json"|"csv"}` gathers the case's persisted evidence and renders a professional report: cover (platform, case id, title, analyst, date, classification), executive summary, scope, indicators, technical findings, threat intelligence (with provider names and retrieval times), network analysis, log analysis, detection evidence (NIDS alerts), timeline, analyst notes, evidence sources, and a disclaimer separating observed facts / calculated values / external intelligence / analyst interpretation. PDF is produced by a dependency-free PDF 1.4 writer; JSON preserves structure; CSV exports IOCs/events. Reports are stored in `REPORT_DIR` and downloadable via `/api/wb/reports/download/<name>`.

### 13. Security considerations
Session authentication with PBKDF2 password hashing and signed cookies; per-client-IP sliding-window rate limiting (429); audit logging of analyst actions; input validation on every endpoint; basename sanitization and UUID storage for uploads (path-traversal protection); extension allowlist and byte-count streaming size caps; an SSRF guard that rejects non-HTTP(S) schemes and private/loopback/link-local/multicast destinations for outbound lookups; secrets from environment only; safe error handling that never leaks stack traces or keys. The platform performs passive observation only — no active scanning of any target.

### 14. Deployment
Local: `python -m Backend.app`. Docker: `docker compose up --build` (host networking + `NET_RAW`/`NET_ADMIN` for capture; named volume for `/data` holding the DB, uploads and reports). For production set `FLASK_DEBUG=False`, a strong `SECRET_KEY`, real `ANALYST_PASSWORD`, and place a TLS-terminating reverse proxy in front. See `Dockerfile` and `docker-compose.yml`.

### 15. Troubleshooting
- **Login fails** — check `ANALYST_USERNAME`/`ANALYST_PASSWORD`; the default account is created on first boot only if no user exists.
- **Provider shows NOT CONFIGURED** — the API key env var is empty; this is expected and honest, not an error.
- **Provider shows TEMPORARILY UNAVAILABLE** — the request timed out or the provider errored; retry later.
- **Geolocation missing** — `GEOIP_ENABLED=False` or the key-free provider was unreachable.
- **Capture state NO_TRAFFIC / PERMISSION_DENIED** — on Windows install Npcap and run elevated; confirm the interface in `/api/monitor/status`.
- **Upload rejected 413** — file exceeds `MAX_UPLOAD_BYTES` (or `MAX_LOG_BYTES` for logs).
- **Upload rejected 400** — extension not in the allowlist.
- **Report download 404** — the report was not generated for that case, or the filename was sanitized away.

---

## 🪟 Windows Live Packet Capture Notes

- To enable **LIVE capture** on Windows, ensure [Npcap](https://npcap.com/) is installed and run the terminal/command prompt as Administrator.
- The dashboard reports the honest capture state rather than a static mode: `LIVE` only while packets are actually arriving, otherwise `NO_TRAFFIC`, `INITIALIZING`, `CAPTURE_ERROR`, `PERMISSION_DENIED`, `NO_INTERFACE`, `DISCONNECTED`, or `STOPPED`.
- If live capture is unavailable, the `[ Simulate Port Scan ]` / `[ Simulate SYN Flood ]` panel remains available as an explicitly-labeled simulation; it never claims to be live capture and never updates capture liveness.

---

## 🛡️ License & Security Notice

Created for defensive cybersecurity monitoring and education. Always ensure proper authorization before deploying packet capture tools.
