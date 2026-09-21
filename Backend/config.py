import os
from pathlib import Path

# Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Database Config
DB_NAME = "nids_database.db"
DB_PATH = os.path.join(BASE_DIR, DB_NAME)

# Detection Rules Configuration
# A Port Scan is detected if a source IP connects to >= PORT_SCAN_THRESHOLD 
# unique destination ports within PORT_SCAN_WINDOW seconds.
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", 8))
PORT_SCAN_WINDOW = int(os.getenv("PORT_SCAN_WINDOW", 10))

# SYN Flood Threshold (packets per window from single IP)
SYN_FLOOD_THRESHOLD = int(os.getenv("SYN_FLOOD_THRESHOLD", 30))
SYN_FLOOD_WINDOW = int(os.getenv("SYN_FLOOD_WINDOW", 5))

# Server Settings
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))
DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ["true", "1", "yes"]
SECRET_KEY = os.getenv("SECRET_KEY", "nids-super-secret-key-2026")

# Sniffer Settings
DEFAULT_INTERFACE = os.getenv("DEFAULT_INTERFACE", None) # None autodetects
AUTO_DEMO_FALLBACK = True
