import os
from pathlib import Path

# Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Database Config
DB_NAME = os.getenv("DB_NAME", "nids_database.db")
DB_PATH = os.path.join(BASE_DIR, DB_NAME)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# --- Detection Rules Configuration ---
# PORT_SCAN: a source IP is flagged when it contacts >= PORT_SCAN_THRESHOLD
# unique destination ports on a single host within PORT_SCAN_WINDOW seconds.
PORT_SCAN_THRESHOLD = _env_int("PORT_SCAN_THRESHOLD", 8)
PORT_SCAN_WINDOW = _env_int("PORT_SCAN_WINDOW", 10)

# SYN_FLOOD: a source IP is flagged when it sends >= SYN_FLOOD_THRESHOLD
# genuine SYN (connection-open) packets within SYN_FLOOD_WINDOW seconds.
SYN_FLOOD_THRESHOLD = _env_int("SYN_FLOOD_THRESHOLD", 30)
SYN_FLOOD_WINDOW = _env_int("SYN_FLOOD_WINDOW", 5)

# Minimum seconds before the same (src, dst, attack_type) can raise another alert.
# Prevents a single sustained attack from flooding the alert store.
ALERT_COOLDOWN = _env_float("ALERT_COOLDOWN", 15.0)

# SUSPICIOUS_PORT: explicit, configurable map of high-risk destination ports.
# Format: "port:SEVERITY:Label,port:SEVERITY:Label,..."
_DEFAULT_SUSPICIOUS_PORTS = "4444:HIGH:Metasploit Default,31337:HIGH:Back Orifice,6667:HIGH:IRC Botnet C2,23:MEDIUM:Telnet Unencrypted"


def _parse_suspicious_ports(raw: str) -> dict:
    ports = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        try:
            port = int(parts[0])
        except (ValueError, IndexError):
            continue
        severity = parts[1].upper() if len(parts) > 1 and parts[1] else "MEDIUM"
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = "MEDIUM"
        label = parts[2] if len(parts) > 2 and parts[2] else f"High-risk port {port}"
        ports[port] = {"severity": severity, "label": label}
    return ports


SUSPICIOUS_PORTS = _parse_suspicious_ports(os.getenv("SUSPICIOUS_PORTS", _DEFAULT_SUSPICIOUS_PORTS))

# --- Asset Monitoring Configuration ---
# The IPv4 address of the asset to monitor. Empty string = monitor ALL traffic (legacy
# global behaviour). Set at runtime via POST /api/monitor/start or env ASSET_IP.
ASSET_IP = os.getenv("ASSET_IP", "")
# Which traffic relationships to monitor: BOTH | INBOUND (to asset) | OUTBOUND (from asset).
ASSET_MODE = os.getenv("ASSET_MODE", "BOTH").upper()

# --- Capture Liveness ---
# A capture is only reported LIVE if a packet was received within this many seconds.
CAPTURE_LIVENESS_SECONDS = _env_float("CAPTURE_LIVENESS_SECONDS", 10.0)

# Window (seconds) over which distinct flows are considered "active".
FLOW_WINDOW = _env_int("FLOW_WINDOW", 60)

# SYN_FLOOD optional rate threshold (SYN packets/second). 0 disables the rate check and
# relies on the count threshold alone.
SYN_FLOOD_RATE_THRESHOLD = _env_float("SYN_FLOOD_RATE_THRESHOLD", 0.0)

# --- Telemetry / Metric Configuration ---
# An alert counts toward "active threats" only if it occurred within this window (seconds).
ACTIVE_THREAT_WINDOW = _env_int("ACTIVE_THREAT_WINDOW", 300)

# Live packet counters are flushed to SQLite in batches (not per packet) to avoid
# one fsync per captured packet. Flush when either limit is reached.
PACKET_FLUSH_COUNT = _env_int("PACKET_FLUSH_COUNT", 50)
PACKET_FLUSH_INTERVAL = _env_float("PACKET_FLUSH_INTERVAL", 2.0)

# --- Server Settings ---
HOST = os.getenv("HOST", "127.0.0.1")
PORT = _env_int("PORT", 5000)
DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ["true", "1", "yes"]
SECRET_KEY = os.getenv("SECRET_KEY", "nids-super-secret-key-2026")

# --- Sniffer Settings ---
DEFAULT_INTERFACE = os.getenv("DEFAULT_INTERFACE", None)  # None autodetects
AUTO_DEMO_FALLBACK = True

# =====================================================================
# Cybersecurity Analyst Workbench configuration
# =====================================================================

# --- Authentication ---
# The workbench (investigation, cases, uploads, reports) is behind a login.
# Credentials come from the environment; a local dev default is provided so the
# platform is usable out-of-the-box, and MUST be overridden in production.
ADMIN_USERNAME = os.getenv("ANALYST_USERNAME", "analyst")
ADMIN_PASSWORD = os.getenv("ANALYST_PASSWORD", "changeme-in-production")
SESSION_LIFETIME_SECONDS = _env_int("SESSION_LIFETIME_SECONDS", 3600)

# --- Rate limiting (in-memory token bucket, per client IP) ---
RATE_LIMIT_REQUESTS = _env_int("RATE_LIMIT_REQUESTS", 120)
RATE_LIMIT_WINDOW = _env_int("RATE_LIMIT_WINDOW", 60)

# --- Uploads / file analysis ---
UPLOAD_DIR = os.path.join(BASE_DIR, os.getenv("UPLOAD_DIRNAME", "uploads"))
MAX_UPLOAD_BYTES = _env_int("MAX_UPLOAD_BYTES", 25 * 1024 * 1024)  # 25 MiB
ALLOWED_UPLOAD_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".pe", ".elf", ".so", ".bin",
    ".py", ".ps1", ".bat", ".cmd", ".sh", ".js", ".vbs",
    ".txt", ".log", ".csv", ".json", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".gz", ".tar", ".7z", ".rar",
}

# --- Log analysis ---
MAX_LOG_BYTES = _env_int("MAX_LOG_BYTES", 100 * 1024 * 1024)  # 100 MiB streamed
LOG_STREAM_CHUNK = _env_int("LOG_STREAM_CHUNK", 1024 * 1024)  # 1 MiB read chunks

# --- Threat-intelligence providers (keys from env only; never hard-coded) ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
# Key-free geolocation provider ("ipwho.is"); set GEOIP_ENABLED=False to disable.
GEOIP_ENABLED = os.getenv("GEOIP_ENABLED", "True").lower() in ["true", "1", "yes"]
PROVIDER_TIMEOUT = _env_float("PROVIDER_TIMEOUT", 8.0)

# --- Reports ---
REPORT_DIR = os.path.join(BASE_DIR, os.getenv("REPORT_DIRNAME", "reports"))
REPORT_CLASSIFICATION = os.getenv("REPORT_CLASSIFICATION", "CONFIDENTIAL - INTERNAL USE")

# --- Demo mode (bundled sample data, strictly labeled, never mixed with real) ---
DEMO_ENABLED = os.getenv("DEMO_ENABLED", "True").lower() in ["true", "1", "yes"]

# --- Google OAuth / OIDC (optional; honest NOT CONFIGURED when absent) ---
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
# Must exactly match an authorized redirect URI in the Google Cloud console.
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "")

# --- Session cookie hardening ---
# Set True when serving over HTTPS so cookies are Secure.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "False").lower() in ["true", "1", "yes"]
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "Lax")

# --- Password policy & reset ---
MIN_PASSWORD_LENGTH = _env_int("MIN_PASSWORD_LENGTH", 8)
PASSWORD_RESET_TTL_SECONDS = _env_int("PASSWORD_RESET_TTL_SECONDS", 1800)
# Stricter per-identity throttle for credential submission.
LOGIN_LIMIT_REQUESTS = _env_int("LOGIN_LIMIT_REQUESTS", 10)
LOGIN_LIMIT_WINDOW = _env_int("LOGIN_LIMIT_WINDOW", 300)

# --- Outbound mail (password-reset delivery). Optional; when unconfigured the
# platform states honestly that reset e-mail delivery is unavailable. ---
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = _env_int("SMTP_PORT", 587)
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "no-reply@analyst-workbench.local")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "True").lower() in ["true", "1", "yes"]
