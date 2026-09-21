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
| `GET` | `/api/attacks` | Attack statistics and category breakdown |
| `GET` | `/api/threats` | Active unresolved security threats |
| `GET` | `/api/detections` | Active rule definitions and recent detections |
| `POST` | `/api/demo/attack` | Trigger controlled simulated attack (`PORT_SCAN` or `SYN_FLOOD`) |
| `POST` | `/api/clear` | Clear all persisted database alerts and reset metrics |

---

## 🧪 Running Automated Tests

Execute the complete pytest test suite:

```powershell
.\venv\Scripts\python.exe -m pytest tests/ -v
```

All 11 unit and integration tests cover detection thresholds, database transactions, and API endpoints.

---

## 🪟 Windows Live Packet Capture Notes

- To enable **LIVE Mode** on Windows, ensure [Npcap](https://npcap.com/) is installed and run the terminal/command prompt as Administrator.
- If Npcap or elevated privileges are missing, NIDS will report `DEMO MODE` and remain fully functional via the `[ Simulate Port Scan ]` action panel.

---

## 🛡️ License & Security Notice

Created for defensive cybersecurity monitoring and education. Always ensure proper authorization before deploying packet capture tools.
