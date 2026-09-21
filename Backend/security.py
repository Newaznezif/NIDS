"""Authentication, authorization, rate limiting and audit helpers for the workbench.

Passwords are stored as PBKDF2 hashes via werkzeug.security. Sessions are
Flask server-side signed cookies; the workbench API rejects unauthenticated
requests with 401. The legacy NIDS monitoring API is intentionally left open
for local/lab use (see README) so existing integrations keep working.
"""
import time
import functools
import logging
from collections import defaultdict, deque
from threading import Lock

from flask import session, request, jsonify, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from . import config
from . import platform_db

logger = logging.getLogger("NIDS.Security")


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False


def ensure_default_user():
    """Create the configured analyst account if no user exists yet."""
    existing = platform_db.get_user(config.ADMIN_USERNAME)
    if existing:
        return
    platform_db.create_user(config.ADMIN_USERNAME, hash_password(config.ADMIN_PASSWORD), role="analyst")
    logger.info("Created default analyst account from environment configuration.")


def authenticate(username: str, password: str) -> bool:
    user = platform_db.get_user(username or "")
    if not user:
        return False
    return verify_password(user["password_hash"], password or "")


def current_user() -> str:
    return session.get("user", "")


# --- rate limiting (in-memory sliding window, per client IP) ---

class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            dq = self._hits[key]
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) >= self.max_requests:
                return False
            dq.append(now)
            return True

    def reset(self):
        with self._lock:
            self._hits.clear()


rate_limiter = RateLimiter(config.RATE_LIMIT_REQUESTS, config.RATE_LIMIT_WINDOW)


def client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def rate_limit_exceeded() -> bool:
    return not rate_limiter.allow(client_ip())


# --- decorators ---

def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("workbench.login_page"))
        return view(*args, **kwargs)
    return wrapper


def api_login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Authentication required.", "authenticated": False}), 401
        return view(*args, **kwargs)
    return wrapper


def audit_event(event: str, detail: str = ""):
    """Record an audit entry for the current request/user."""
    try:
        platform_db.audit(current_user() or "anonymous", event, detail, client_ip())
    except Exception as e:  # auditing must never break the request path
        logger.debug(f"Audit write failed: {e}")
