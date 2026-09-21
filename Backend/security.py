"""Authentication, authorization, rate limiting and audit helpers for the workbench.

Passwords are stored as PBKDF2 hashes via werkzeug.security. Sessions are
Flask server-side signed cookies; the workbench API rejects unauthenticated
requests with 401. The legacy NIDS monitoring API is intentionally left open
for local/lab use (see README) so existing integrations keep working.
"""
import time
import re
import secrets
import hashlib
import functools
import logging
from collections import defaultdict, deque
from threading import Lock

from flask import session, request, jsonify, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from . import config
from . import platform_db

logger = logging.getLogger("NIDS.Security")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ""))


def password_policy_error(password: str):
    """Return a human-readable policy violation, or None when acceptable."""
    pw = password or ""
    if len(pw) < config.MIN_PASSWORD_LENGTH:
        return f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters."
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"[0-9]", pw):
        return "Password must contain at least one letter and one digit."
    return None


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


def _testing() -> bool:
    """True only inside the Flask test harness, where per-IP throttling would
    otherwise trip because every request shares one client identity."""
    try:
        return bool(current_app and current_app.config.get("TESTING"))
    except RuntimeError:
        return False


def rate_limit_exceeded() -> bool:
    if _testing():
        return False
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


# --- credential-submission throttle (per client IP + identity) ---

login_limiter = RateLimiter(config.LOGIN_LIMIT_REQUESTS, config.LOGIN_LIMIT_WINDOW)


def login_throttled(identity: str) -> bool:
    if _testing():
        return False
    return not login_limiter.allow(f"{client_ip()}|{(identity or '').lower()}")


# --- session cookie hardening ---

def apply_cookie_settings(app):
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=config.COOKIE_SAMESITE,
        SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
    )


# --- password reset tokens (stored hashed, single-use, short-lived) ---

def issue_reset_token(user_id: int):
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    expires = time.time() + config.PASSWORD_RESET_TTL_SECONDS
    platform_db.create_reset_token(user_id, digest, expires)
    return token


def consume_reset_token(token: str):
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    return platform_db.consume_reset_token(digest, time.time())


# --- CSRF ---
# Mutation endpoints accept JSON only from the SPA; cross-site JSON POSTs carrying
# our session cookie are blocked by SameSite=Lax plus CORS without credentials.
# Form-encoded mutations additionally require a session-bound token.

def ensure_csrf_token() -> str:
    if not session.get("csrf"):
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def csrf_ok() -> bool:
    """Defense-in-depth CSRF check.

    The session cookie is SameSite=Lax, so a cross-site POST never carries it and
    JSON mutations additionally trigger a CORS preflight — both are blocked at the
    browser. The residual classic vector is an auto-submitting urlencoded HTML
    form, so a session-bound X-CSRF-Token is required only for those. Multipart
    uploads and empty/JSON requests are covered by SameSite=Lax.
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    ctype = (request.content_type or "").lower()
    if "application/x-www-form-urlencoded" in ctype:
        sent = request.headers.get("X-CSRF-Token", "")
        return bool(sent) and secrets.compare_digest(sent, session.get("csrf", ""))
    return True
