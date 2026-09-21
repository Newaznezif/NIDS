import os
import sys
import logging
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from .config import HOST, PORT, DEBUG, SECRET_KEY, BASE_DIR
from .database import init_db, get_all_alerts, get_stats, clear_all_data
from .detector import IntrusionDetector
from .sniffer import NetworkSniffer
from .socket_handler import socketio, init_socketio

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("NIDS.App")

# Paths for static frontend assets
FRONTEND_DIR = os.path.join(BASE_DIR, "Frontend")

# Initialize Flask app
app = Flask(__name__, static_folder=FRONTEND_DIR)
app.config["SECRET_KEY"] = SECRET_KEY
CORS(app)

# Initialize Real-time Socket.IO
init_socketio(app)

# Global Instance of Detection Engine & Sniffer
detector = IntrusionDetector()
sniffer = NetworkSniffer(detector=detector)

# Initialize Database Schema & Sniffer on Startup
with app.app_context():
    init_db()
    sniffer.start()

# --- STATIC DASHBOARD ROUTES ---

@app.route("/")
def index():
    """Serves the main SOC Security Dashboard page."""
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/css/<path:filename>")
def serve_css(filename):
    """Serves CSS assets."""
    return send_from_directory(os.path.join(FRONTEND_DIR, "css"), filename)

@app.route("/js/<path:filename>")
def serve_js(filename):
    """Serves JS assets."""
    return send_from_directory(os.path.join(FRONTEND_DIR, "js"), filename)

# --- REST API ENDPOINTS ---

@app.route("/api/health", methods=["GET"])
def health_check():
    """Returns application health status and sniffer mode."""
    status_info = sniffer.get_status_info()
    return jsonify({
        "status": "healthy",
        "service": "Network Intrusion Detection System (NIDS)",
        "mode": status_info["mode"],
        "sniffer": status_info,
        "database": "connected"
    }), 200

@app.route("/api/status", methods=["GET"])
def get_system_status():
    """Returns current network sniffer status and mode (LIVE vs DEMO)."""
    return jsonify(sniffer.get_status_info()), 200

@app.route("/api/stats", methods=["GET"])
def get_dashboard_stats():
    """Returns aggregated security stats, packet metrics, and threat distribution."""
    stats = get_stats()
    stats["mode"] = sniffer.mode
    stats["sniffer_status"] = sniffer.get_status_info()
    return jsonify(stats), 200

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Returns recent alerts list with optional filtering by limit, severity, or attack_type."""
    limit = request.args.get("limit", default=100, type=int)
    severity = request.args.get("severity", default=None, type=str)
    attack_type = request.args.get("attack_type", default=None, type=str)

    alerts = get_all_alerts(limit=limit, severity=severity, attack_type=attack_type)
    return jsonify({
        "count": len(alerts),
        "alerts": alerts
    }), 200

@app.route("/api/attacks", methods=["GET"])
def get_attacks_history():
    """Returns security attack history and breakdown."""
    alerts = get_all_alerts(limit=50)
    stats = get_stats()
    return jsonify({
        "total_attacks": stats["total_attacks"],
        "attack_types": stats["attack_types"],
        "recent_attacks": alerts
    }), 200

@app.route("/api/threats", methods=["GET"])
def get_active_threats():
    """Returns currently active unresolved threats."""
    all_alerts = get_all_alerts(limit=100)
    active = [a for a in all_alerts if a.get("status") == "ACTIVE"]
    return jsonify({
        "count": len(active),
        "active_threats": active
    }), 200

@app.route("/api/detections", methods=["GET"])
def get_detections():
    """Returns detection engine rules summary and triggered detections."""
    alerts = get_all_alerts(limit=50)
    return jsonify({
        "engine": "Rule-Based Intrusion Detector",
        "rules": [
            {"name": "PORT_SCAN", "threshold": detector.port_scan_threshold, "window_seconds": detector.port_scan_window},
            {"name": "SYN_FLOOD", "threshold": 30, "window_seconds": 5},
            {"name": "SUSPICIOUS_PORT", "ports": [4444, 31337, 6667, 23]}
        ],
        "recent_detections": alerts
    }), 200

@app.route("/api/demo/attack", methods=["POST"])
def trigger_demo_attack():
    """
    Simulates a network attack (Port Scan, SYN Flood, or Suspicious Port)
    and passes simulated packets through the full detection pipeline.
    """
    payload = request.get_json(silent=True) or {}
    attack_type = payload.get("attack_type", "PORT_SCAN").upper()
    source_ip = payload.get("source_ip", f"192.168.1.{os.urandom(1)[0]}")
    target_ip = payload.get("target_ip", "192.168.1.10")

    if attack_type == "SYN_FLOOD":
        result = sniffer.trigger_demo_syn_flood(source_ip=source_ip, target_ip=target_ip)
    else: # Default: PORT_SCAN
        ports_count = payload.get("ports_count", 10)
        result = sniffer.trigger_demo_port_scan(source_ip=source_ip, target_ip=target_ip, ports_count=ports_count)

    # Emit socket update for stats refresh
    socketio.emit("stats_update", get_stats())

    return jsonify({
        "message": f"Demo {attack_type} attack executed through detection pipeline.",
        "result": result
    }), 200

@app.route("/api/clear", methods=["POST"])
def reset_system():
    """Resets all alerts, packet logs, stats, and detector memory."""
    clear_all_data()
    detector.reset()
    socketio.emit("stats_update", get_stats())
    return jsonify({"message": "System data and detector state successfully cleared."}), 200

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found", "path": request.path}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error", "details": str(e)}), 500

if __name__ == "__main__":
    logger.info(f"Starting NIDS Backend on http://{HOST}:{PORT}")
    socketio.run(app, host=HOST, port=PORT, debug=DEBUG, allow_unsafe_werkzeug=True)
