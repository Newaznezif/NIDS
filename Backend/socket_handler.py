import logging
from flask import Flask
from flask_socketio import SocketIO, emit
from .alert_engine import register_socket_emitter

logger = logging.getLogger("NIDS.SocketHandler")

socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")

def init_socketio(app: Flask):
    """Initializes SocketIO with Flask app and registers socket event listeners."""
    socketio.init_app(app)

    @socketio.on("connect")
    def handle_connect():
        logger.info("Dashboard client connected via Socket.IO")
        emit("connection_status", {"status": "connected", "message": "Connected to NIDS Real-Time Alert Feed"})

    @socketio.on("disconnect")
    def handle_disconnect():
        logger.info("Dashboard client disconnected from Socket.IO")

    @socketio.on("ping_server")
    def handle_ping():
        emit("pong_client", {"status": "ok"})

    # Register emitter callback in Alert Engine
    register_socket_emitter(broadcast_event)
    logger.info("SocketIO initialized successfully.")

def broadcast_event(event_name: str, data: dict):
    """Broadcasts a socket event to all connected dashboard clients."""
    try:
        socketio.emit(event_name, data)
    except Exception as e:
        logger.error(f"Error emitting socket event '{event_name}': {e}")
