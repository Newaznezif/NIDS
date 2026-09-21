# Network Intrusion Detection System (NIDS)

A high-performance, rule-based Network Intrusion Detection System (NIDS) built with Python Flask, Scapy, SQLite, Socket.IO, and a modern SOC Security Dashboard.

> **Disclaimer**: This tool is designed strictly for educational, defensive, and authorized security monitoring purposes. Live network packet capture and testing must only be executed on networks and devices for which you have explicit authorization.

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
│   ├── app.py              # Main Flask REST API & Web Server
│   ├── config.py           # Thresholds & Server Configuration
│   ├── database.py         # SQLite Schema & Query Helpers
│   ├── models.py           # Dataclasses (Packet, Alert)
│   ├── analyzer.py         # Packet Normalizer
│   ├── detector.py         # Stateful Intrusion Detection Engine
│   ├── alert_engine.py     # Alert Processor & Persister
│   ├── sniffer.py          # Scapy Sniffer & Demo Simulator
│   └── socket_handler.py   # Socket.IO Listener & Broadcaster
│
├── Frontend/
│   ├── index.html          # SOC Security Dashboard HTML
│   ├── css/
│   │   └── style.css       # Cybersecurity Dark Theme Styles
│   └── js/
│       └── dashboard.js    # Dashboard Controller & Chart.js Engine
│
├── tests/
│   ├── test_detector.py    # Unit tests for Port Scan rules
│   ├── test_db.py          # Unit tests for SQLite operations
│   └── test_api.py         # Integration tests for REST API
│
├── requirements.txt        # Python Dependencies
├── .env.example            # Environment variables template
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
http://127.0.0.1:5000
```

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

---

## 🧪 Running Automated Tests

Execute the complete pytest test suite:

```powershell
.\venv\Scripts\python.exe -m pytest tests/ -v
```

All 51 unit and integration tests cover detection thresholds, asset filtering, capture-state transitions, database transactions, and API endpoints.

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

## 🪟 Windows Live Packet Capture Notes

- To enable **LIVE capture** on Windows, ensure [Npcap](https://npcap.com/) is installed and run the terminal/command prompt as Administrator.
- The dashboard reports the honest capture state rather than a static mode: `LIVE` only while packets are actually arriving, otherwise `NO_TRAFFIC`, `INITIALIZING`, `CAPTURE_ERROR`, `PERMISSION_DENIED`, `NO_INTERFACE`, `DISCONNECTED`, or `STOPPED`.
- If live capture is unavailable, the `[ Simulate Port Scan ]` / `[ Simulate SYN Flood ]` panel remains available as an explicitly-labeled simulation; it never claims to be live capture and never updates capture liveness.

---

## 🛡️ License & Security Notice

Created for defensive cybersecurity monitoring and education. Always ensure proper authorization before deploying packet capture tools.
