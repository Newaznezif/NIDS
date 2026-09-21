import logging
from typing import Optional, Dict, Any
from .models import Alert
from .database import save_alert

logger = logging.getLogger("NIDS.AlertEngine")

# Optional reference to socket broadcast handler
_socket_emitter = None

def register_socket_emitter(emitter_func):
    """Registers a callback function to broadcast real-time alerts via WebSocket."""
    global _socket_emitter
    _socket_emitter = emitter_func
    logger.info("WebSocket emitter registered with Alert Engine.")

def process_alert(alert: Alert) -> Dict[str, Any]:
    """
    Processes a generated Alert:
    1. Converts alert to dict.
    2. Persists to SQLite database.
    3. Broadcasts via WebSocket if active.
    Returns the saved alert payload.
    """
    alert_dict = alert.to_dict()
    
    # Save to SQLite DB
    db_id = save_alert(alert_dict)
    if db_id:
        alert_dict["id"] = db_id

    logger.warning(
        f"[ALERT GENERATED] #{alert_dict.get('id')} - Type: {alert_dict.get('attack_type')} | "
        f"Severity: {alert_dict.get('severity')} | Src: {alert_dict.get('source_ip')} -> Dst: {alert_dict.get('destination_ip')}"
    )

    # Broadcast real-time websocket alert
    if _socket_emitter:
        try:
            _socket_emitter("new_alert", alert_dict)
        except Exception as e:
            logger.error(f"Failed to emit socket alert: {e}")

    return alert_dict
