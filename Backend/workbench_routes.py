"""Cybersecurity Analyst Workbench routes (Blueprint).

All /api/wb/* endpoints require an authenticated session and are rate-limited
and audited. The legacy NIDS /api/* endpoints are unchanged.
"""
import os
import re
import secrets
import logging
from datetime import datetime

from flask import Blueprint, jsonify, request, session, send_from_directory, redirect, url_for, render_template_string

from . import config, platform_db, security
from . import ioc_engine, encoding_tools, network_tools
from . import analysis_ip, analysis_url, analysis_domain, analysis_hash
from . import file_analysis, log_analysis, reports, demo_data, providers
from . import google_oauth, mail, geography

logger = logging.getLogger("NIDS.Workbench")

wb = Blueprint("workbench", __name__)

THEME_BOOTSTRAP = """<script>(function(){var t='system';try{t=localStorage.getItem('wb-theme')||'system'}catch(e){}
var dark=t==='dark'||(t!=='light'&&!(window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches));
document.documentElement.setAttribute('data-theme',dark?'dark':'light');})();</script>"""

LOGO_SVG = """<svg class="logo" width="34" height="34" viewBox="0 0 64 64" aria-hidden="true">
<rect x="4" y="4" width="56" height="56" rx="14" fill="var(--accent-cyan,#0e7490)"/>
<path d="M32 14 L46 20 V32 C46 41 40 47 32 50 C24 47 18 41 18 32 V20 Z" fill="none" stroke="#04121a" stroke-width="4" stroke-linejoin="round"/>
<path d="M25 32 l5 5 l10 -11" fill="none" stroke="#04121a" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

AUTH_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} &middot; Cybersecurity Analyst Workbench</title>
<link rel="stylesheet" href="/css/style.css">
""" + THEME_BOOTSTRAP + """
<style>
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
  background:var(--bg-dark);color:var(--text-primary);font-family:var(--font-sans)}
.auth-card{width:100%;max-width:400px;background:var(--bg-card);border:1px solid var(--border-color);
  border-radius:14px;padding:34px 32px}
.auth-brand{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.auth-brand .name{font-size:15px;font-weight:600;letter-spacing:.02em}
.auth-card h1{font-size:21px;margin:18px 0 4px;letter-spacing:-.01em}
.auth-sub{color:var(--text-secondary);font-size:13px;margin-bottom:22px}
.field{margin-bottom:14px}
.field label{display:block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--text-secondary);margin-bottom:6px}
.field input{width:100%;background:var(--bg-input);border:1px solid var(--border-input);border-radius:8px;
  color:var(--text-primary);padding:10px 12px;font-size:14px;font-family:var(--font-sans)}
.field input:focus{outline:none;border-color:var(--accent-cyan)}
.btn-primary{width:100%;background:var(--accent-cyan);border:none;color:#04121a;font-weight:600;
  padding:11px;border-radius:8px;font-size:14px;cursor:pointer;margin-top:6px}
.btn-primary:hover{filter:brightness(1.08)}
.btn-google{width:100%;display:flex;align-items:center;justify-content:center;gap:10px;
  background:var(--bg-input);border:1px solid var(--border-input);color:var(--text-primary);
  padding:10px;border-radius:8px;font-size:14px;cursor:pointer;text-decoration:none}
.btn-google:hover{border-color:var(--border-bright)}
.divider{display:flex;align-items:center;gap:10px;color:var(--text-muted);font-size:11px;
  text-transform:uppercase;letter-spacing:.08em;margin:18px 0}
.divider:before,.divider:after{content:"";flex:1;height:1px;background:var(--border-color)}
.err{color:var(--sev-high);font-size:12.5px;margin-top:12px;min-height:16px}
.ok{color:var(--sev-low);font-size:12.5px;margin-top:12px}
.links{margin-top:18px;display:flex;justify-content:space-between;font-size:12.5px}
.links a{color:var(--accent-cyan);text-decoration:none}
.links a:hover{text-decoration:underline}
.note{margin-top:20px;padding-top:14px;border-top:1px solid var(--border-color);
  color:var(--text-muted);font-size:11.5px;line-height:1.6}
.google-off{margin-top:10px;color:var(--text-muted);font-size:11.5px}
</style></head><body><div class="auth-wrap"><div class="auth-card">
<div class="auth-brand">""" + LOGO_SVG + """<span class="name">Cybersecurity Analyst Workbench</span></div>
<h1>{{ heading }}</h1>
<div class="auth-sub">{{ subtext }}</div>
<form method="post" action="{{ action }}">
{{ fields }}
<button class="btn-primary" type="submit">{{ submit }}</button>
<div class="err">{{ error }}</div>
<div class="ok">{{ notice }}</div>
</form>
{{ google_block }}
<div class="links">{{ links }}</div>
<div class="note">Real evidence &middot; traceable results &middot; professional reporting.
No result is ever fabricated; unconfigured sources report NOT CONFIGURED.</div>
</div></div></body></html>"""


def _field(name, label, type="text", autocomplete="", value=""):
    return (f'<div class="field"><label for="{name}">{label}</label>'
            f'<input id="{name}" name="{name}" type="{type}" autocomplete="{autocomplete}" '
            f'value="{value}" required></div>')


def _render_auth(title, heading, subtext, action, fields, submit, links,
                 error="", notice="", google_block=""):
    return render_template_string(
        AUTH_PAGE, title=title, heading=heading, subtext=subtext, action=action,
        fields=fields, submit=submit, links=links, error=error, notice=notice,
        google_block=google_block)


def _google_block():
    if google_oauth.configured():
        return ('<div class="divider">or</div>'
                '<a class="btn-google" href="/api/wb/auth/google">'
                '<svg width="16" height="16" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9.1 3.6l6.8-6.8C35.8 2.4 30.2 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.2C12.4 13.6 17.7 9.5 24 9.5z"/><path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.3 5.5-4.9 7.2l7.6 5.9c4.5-4.1 7.1-10.2 7.1-17.6z"/><path fill="#FBBC05" d="M10.5 28.6c-.5-1.4-.7-3-.7-4.6s.3-3.2.7-4.6l-7.9-6.2C.9 16.5 0 20.1 0 24s.9 7.5 2.6 10.8l7.9-6.2z"/><path fill="#34A853" d="M24 48c6.2 0 11.4-2 15.2-5.5l-7.6-5.9c-2.1 1.4-4.8 2.3-7.6 2.3-6.3 0-11.6-4.1-13.5-9.9l-7.9 6.2C6.5 42.6 14.6 48 24 48z"/></svg>'
                'Continue with Google</a>')
    return ('<div class="google-off">Google sign-in is not configured on this server. '
            'Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI to enable it.</div>')


@wb.before_request
def _guard():
    if security.rate_limit_exceeded():
        return jsonify({"error": "Rate limit exceeded. Slow down."}), 429
    if session.get("user") and not security.csrf_ok():
        return jsonify({"error": "CSRF token missing or invalid."}), 403


# --- pages ---

@wb.route("/login", methods=["GET"])
def login_page():
    if session.get("user"):
        return redirect(url_for("workbench.workbench_page"))
    return _render_auth(
        "Login", "Welcome back", "Sign in to continue to your workspace.",
        "/api/wb/login",
        _field("username", "Email or username", "text", "username") +
        _field("password", "Password", "password", "current-password"),
        "Login",
        '<a href="/signup">Create account</a><a href="/forgot">Forgot password?</a>',
        google_block=_google_block())


@wb.route("/signup", methods=["GET"])
def signup_page():
    if session.get("user"):
        return redirect(url_for("workbench.workbench_page"))
    return _render_auth(
        "Create account", "Create your account", "One email and a strong password. That's it.",
        "/api/wb/register",
        _field("display_name", "Name (optional)") +
        _field("email", "Email", "email", "email") +
        _field("password", "Password", "password", "new-password"),
        "Create account",
        '<a href="/login">Sign in instead</a><span></span>',
        google_block=_google_block())


@wb.route("/forgot", methods=["GET"])
def forgot_page():
    return _render_auth(
        "Forgot password", "Reset your password", "Enter your account email and we'll send a reset link.",
        "/api/wb/forgot",
        _field("email", "Email", "email", "email"),
        "Send reset link",
        '<a href="/login">Back to sign in</a><span></span>')


@wb.route("/reset", methods=["GET"])
def reset_page():
    token = request.args.get("token", "")
    return _render_auth(
        "Choose a new password", "Choose a new password", "Pick a strong password you don't use elsewhere.",
        "/api/wb/reset",
        f'<input type="hidden" name="token" value="{token}">' +
        _field("password", "New password", "password", "new-password"),
        "Set password",
        '<a href="/login">Back to sign in</a><span></span>')


@wb.route("/workbench", methods=["GET"])
@security.login_required
def workbench_page():
    from .app import FRONTEND_DIR
    return send_from_directory(FRONTEND_DIR, "workbench.html")


# --- auth ---

def _establish_session(user):
    session.clear()
    session["user"] = user["username"]
    session["uid"] = user["id"]
    session.permanent = True
    security.ensure_csrf_token()


def _session_payload(user):
    return {
        "authenticated": True,
        "user": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "email": user.get("email") or "",
        "auth_provider": user.get("auth_provider") or "local",
        "theme": user.get("theme") or "system",
        "csrf_token": security.ensure_csrf_token(),
    }


@wb.route("/api/wb/register", methods=["POST"])
def register():
    data = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    display_name = (data.get("display_name") or "").strip()
    if security.login_throttled(email):
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    if not security.valid_email(email):
        return _auth_fail("Enter a valid email address.")
    err = security.password_policy_error(password)
    if err:
        return _auth_fail(err)
    if platform_db.get_user_by_email(email):
        return _auth_fail("An account with that email already exists. Try signing in.")
    username = email
    if platform_db.get_user(username):
        return _auth_fail("An account with that email already exists. Try signing in.")
    platform_db.create_user(username, security.hash_password(password), role="analyst",
                            email=email, display_name=display_name or email.split("@")[0],
                            auth_provider="local")
    user = platform_db.get_user_by_email(email)
    _establish_session(user)
    security.audit_event("register", f"email={email}")
    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify(_session_payload(user)), 200
    return redirect(url_for("workbench.workbench_page"))


def _auth_fail(message, status=401):
    security.audit_event("auth_rejected", message)
    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({"authenticated": False, "error": message}), status
    return _render_auth("Login", "Welcome back", "Sign in to continue to your workspace.",
                        "/api/wb/login",
                        _field("username", "Email or username", "text", "username") +
                        _field("password", "Password", "password", "current-password"),
                        "Login",
                        '<a href="/signup">Create account</a><a href="/forgot">Forgot password?</a>',
                        error=message, google_block=_google_block()), status


@wb.route("/api/wb/login", methods=["POST"])
def login():
    data = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    identity = (data.get("username") or data.get("email") or "").strip()
    password = data.get("password") or ""
    if security.login_throttled(identity):
        return _auth_fail("Too many attempts. Try again later.", 429)
    user = platform_db.get_user_by_email(identity.lower()) or platform_db.get_user(identity)
    if user and (user.get("auth_provider") or "local") == "local" \
            and security.verify_password(user["password_hash"], password):
        _establish_session(user)
        security.audit_event("login", f"user={user['username']}")
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify(_session_payload(user)), 200
        return redirect(url_for("workbench.workbench_page"))
    # Same message whether the account exists or not (enumeration protection).
    return _auth_fail("Invalid credentials.")


@wb.route("/api/wb/forgot", methods=["POST"])
def forgot():
    data = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    email = (data.get("email") or "").strip().lower()
    generic = ("If an account exists for that email, a reset link has been issued. "
               "Check your inbox.")
    user = platform_db.get_user_by_email(email) if security.valid_email(email) else None
    if user:
        token = security.issue_reset_token(user["id"])
        reset_url = url_for("workbench.reset_page", _external=True) + f"?token={token}"
        delivered = mail.send_reset_email(user.get("email") or email, reset_url)
        security.audit_event("password_reset_requested",
                             f"email={email} delivered={delivered}")
        if not delivered and (request.is_json or request.headers.get("Accept") == "application/json"):
            return jsonify({"message": generic,
                            "delivery": "UNAVAILABLE",
                            "detail": "No mail transport is configured on this server "
                                      "(SMTP_HOST). Contact your administrator."}), 200
    else:
        security.audit_event("password_reset_requested", "email=unknown")
    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({"message": generic, "delivery": "SENT" if mail.configured() else "UNAVAILABLE"}), 200
    return _render_auth("Forgot password", "Check your email", generic, "/api/wb/forgot",
                        _field("email", "Email", "email", "email"), "Send reset link",
                        '<a href="/login">Back to sign in</a><span></span>')


@wb.route("/api/wb/reset", methods=["POST"])
def reset():
    data = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    token = (data.get("token") or "").strip()
    password = data.get("password") or ""
    err = security.password_policy_error(password)
    user_id = security.consume_reset_token(token) if not err else None
    if err or user_id is None:
        return _auth_fail("This reset link is invalid or has expired. Request a new one.")
    platform_db.set_password(user_id, security.hash_password(password))
    user = platform_db.get_user_by_id(user_id)
    security.audit_event("password_reset_completed", f"user={user['username']}")
    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({"message": "Password updated. You can now sign in."}), 200
    return redirect(url_for("workbench.login_page"))


@wb.route("/api/wb/logout", methods=["POST"])
def logout():
    user = session.get("user", "")
    security.audit_event("logout", f"user={user}")
    session.clear()
    return jsonify({"authenticated": False}), 200


@wb.route("/api/wb/session", methods=["GET"])
def session_info():
    if not session.get("user"):
        return jsonify({"authenticated": False, "user": ""}), 200
    user = platform_db.get_user(session["user"]) or {}
    return jsonify(_session_payload(user)), 200


# --- Google OIDC ---

@wb.route("/api/wb/auth/config", methods=["GET"])
def auth_config():
    return jsonify({
        "google": {"configured": google_oauth.configured()},
        "password_reset_delivery": "smtp" if mail.configured() else "none",
    }), 200


@wb.route("/api/wb/auth/google", methods=["GET"])
def google_start():
    if not google_oauth.configured():
        return jsonify({"error": "Google authentication is not configured on this server.",
                        "configured": False}), 503
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    session["oauth_nonce"] = nonce
    return redirect(google_oauth.auth_url(state, nonce))


@wb.route("/api/wb/auth/google/callback", methods=["GET"])
def google_callback():
    if not google_oauth.configured():
        return jsonify({"error": "Google authentication is not configured on this server."}), 503
    state = request.args.get("state", "")
    expected_state = session.pop("oauth_state", "")
    nonce = session.pop("oauth_nonce", "")
    if not state or not expected_state or not secrets.compare_digest(state, expected_state):
        security.audit_event("oauth_state_mismatch", "")
        return jsonify({"error": "OAuth state validation failed. Start the sign-in again."}), 403
    error = request.args.get("error")
    if error:
        return jsonify({"error": f"Google sign-in was not completed ({error})."}), 401
    code = request.args.get("code", "")
    if not code:
        return jsonify({"error": "No authorization code returned by Google."}), 400
    try:
        tokens = google_oauth.exchange_code(code)
        claims = google_oauth.verify_id_token(tokens["id_token"], nonce)
    except ValueError as e:
        security.audit_event("oauth_token_rejected", str(e))
        return jsonify({"error": "Google token validation failed. Start the sign-in again."}), 401
    except Exception as e:
        logger.warning("Google token exchange failed: %s", e)
        return jsonify({"error": "Could not reach Google to complete sign-in."}), 502
    profile = google_oauth.profile_from_claims(claims)
    if not profile["email"] or not profile["email_verified"]:
        return jsonify({"error": "Google account has no verified email address."}), 401
    user = platform_db.get_user_by_email(profile["email"])
    if not user:
        platform_db.create_user(profile["email"], security.hash_password(secrets.token_urlsafe(32)),
                                role="analyst", email=profile["email"],
                                display_name=profile["name"] or profile["email"].split("@")[0],
                                auth_provider="google")
        user = platform_db.get_user_by_email(profile["email"])
        security.audit_event("oauth_account_created", f"email={profile['email']}")
    _establish_session(user)
    security.audit_event("oauth_login", f"user={user['username']}")
    return redirect(url_for("workbench.workbench_page"))


# --- profile & appearance ---

@wb.route("/api/wb/profile", methods=["GET"])
@security.api_login_required
def profile():
    user = platform_db.get_user(session["user"]) or {}
    return jsonify({
        "username": user.get("username", ""),
        "display_name": user.get("display_name") or user.get("username", ""),
        "email": user.get("email") or "",
        "auth_provider": user.get("auth_provider") or "local",
        "theme": user.get("theme") or "system",
        "created_at": user.get("created_at", ""),
        "role": user.get("role", ""),
    }), 200


@wb.route("/api/wb/profile", methods=["POST"])
@security.api_login_required
def update_profile():
    payload = request.get_json(silent=True) or {}
    display_name = (payload.get("display_name") or "").strip()
    if len(display_name) > 80:
        return jsonify({"error": "Display name too long."}), 400
    user = platform_db.get_user(session["user"])
    platform_db.update_profile(user["id"], display_name=display_name or None)
    security.audit_event("profile_updated", f"user={user['username']}")
    return jsonify({"updated": True}), 200


@wb.route("/api/wb/profile/password", methods=["POST"])
@security.api_login_required
def change_password():
    payload = request.get_json(silent=True) or {}
    current = payload.get("current_password") or ""
    new = payload.get("new_password") or ""
    user = platform_db.get_user(session["user"])
    if (user.get("auth_provider") or "local") != "local":
        return jsonify({"error": "This account signs in with Google; passwords are managed there."}), 400
    if not security.verify_password(user["password_hash"], current):
        return jsonify({"error": "Current password is incorrect."}), 401
    err = security.password_policy_error(new)
    if err:
        return jsonify({"error": err}), 400
    platform_db.set_password(user["id"], security.hash_password(new))
    security.audit_event("password_changed", f"user={user['username']}")
    return jsonify({"updated": True}), 200


@wb.route("/api/wb/appearance", methods=["GET", "POST"])
def appearance():
    theme = "system"
    if session.get("user"):
        user = platform_db.get_user(session["user"])
        theme = (user or {}).get("theme") or "system"
    if request.method == "GET":
        return jsonify({"theme": theme}), 200
    payload = request.get_json(silent=True) or {}
    wanted = (payload.get("theme") or "").strip()
    if wanted not in ("system", "light", "dark"):
        return jsonify({"error": "theme must be system, light or dark"}), 400
    if session.get("user"):
        user = platform_db.get_user(session["user"])
        platform_db.update_profile(user["id"], theme=wanted)
    return jsonify({"theme": wanted}), 200


# --- dashboard ---

@wb.route("/api/wb/dashboard", methods=["GET"])
@security.api_login_required
def dashboard():
    cases = platform_db.list_cases(demo=0)
    invs = platform_db.recent_investigations(limit=20, demo=0)
    from .database import get_all_alerts, get_stats
    ioc_counter = {}
    for inv in invs:
        ioc_counter[inv["ioc_type"]] = ioc_counter.get(inv["ioc_type"], 0) + 1
    return jsonify({
        "active_cases": [c for c in cases if c["status"] in ("OPEN", "IN_PROGRESS")],
        "recent_cases": cases[:10],
        "recent_investigations": invs,
        "recent_alerts": get_all_alerts(limit=10),
        "ioc_statistics": ioc_counter,
        "analysis_activity": platform_db.recent_audit(limit=15),
        "providers": providers.provider_statuses(),
        "recent_reports": platform_db.recent_reports(limit=10),
        "nids": get_stats(),
    }), 200


# --- investigation center ---

@wb.route("/api/wb/investigate", methods=["POST"])
@security.api_login_required
def investigate():
    payload = request.get_json(silent=True) or {}
    value = (payload.get("value") or "").strip()
    if not value:
        return jsonify({"error": "value is required"}), 400
    itype = ioc_engine.detect_type(value)
    if itype == "UNKNOWN":
        return jsonify({"error": "Unrecognized indicator type. Provide an IP, URL, domain, "
                                 "or MD5/SHA1/SHA256/SHA512 hash.", "detected_type": "UNKNOWN"}), 400
    if itype in ("IPv4", "IPv6"):
        result = analysis_ip.analyze(value)
    elif itype == "URL":
        result = analysis_url.analyze(value)
    elif itype == "DOMAIN":
        result = analysis_domain.analyze(value)
    elif itype in ("MD5", "SHA1", "SHA256", "SHA512"):
        result = analysis_hash.analyze(value)
    else:
        return jsonify({"error": f"No analyzer for type {itype}", "detected_type": itype}), 400

    inv_id = platform_db.save_investigation(itype, value, result, analyst=security.current_user())
    geography.record_from_investigation(result, itype, value)
    security.audit_event("investigate", f"{itype}:{value}")
    return jsonify({"detected_type": itype, "investigation_id": inv_id, "result": result}), 200


@wb.route("/api/wb/map", methods=["GET"])
@security.api_login_required
def investigation_map():
    return jsonify(geography.map_payload()), 200


@wb.route("/api/wb/investigations", methods=["GET"])
@security.api_login_required
def investigations():
    return jsonify({"investigations": platform_db.recent_investigations(limit=100, demo=0)}), 200


@wb.route("/api/wb/investigation/<int:inv_id>", methods=["GET"])
@security.api_login_required
def investigation(inv_id):
    inv = platform_db.get_investigation(inv_id)
    if not inv:
        return jsonify({"error": "Investigation not found"}), 404
    return jsonify(inv), 200


# --- IOC extraction ---

@wb.route("/api/wb/ioc/extract", methods=["POST"])
@security.api_login_required
def extract():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text") or ""
    extracted = ioc_engine.extract_iocs(text)
    return jsonify({"extracted": extracted, "flat": ioc_engine.flatten(extracted),
                    "provenance": "EXTRACTED",
                    "source": payload.get("source", "analyst-provided text")}), 200


# --- encoding ---

@wb.route("/api/wb/encode", methods=["POST"])
@security.api_login_required
def encode():
    payload = request.get_json(silent=True) or {}
    try:
        out = encoding_tools.run(payload.get("operation"), payload.get("codec"), payload.get("data", ""))
    except encoding_tools.CodecError as e:
        return jsonify({"error": str(e)}), 400
    security.audit_event("encode", f"{payload.get('operation')}/{payload.get('codec')}")
    return jsonify(out), 200


# --- network tools ---

@wb.route("/api/wb/network/cidr", methods=["POST"])
@security.api_login_required
def net_cidr():
    payload = request.get_json(silent=True) or {}
    return jsonify(network_tools.cidr_analysis(payload.get("cidr", ""))), 200


@wb.route("/api/wb/network/dns", methods=["POST"])
@security.api_login_required
def net_dns():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    qtype = (payload.get("qtype") or "A").upper()
    if not name:
        return jsonify({"error": "name is required"}), 400
    try:
        records = network_tools.dns_query(name, qtype)
        return jsonify({"name": name, "qtype": qtype, "records": records,
                        "provenance": "OBSERVED" if records else "UNAVAILABLE",
                        "source": "DNS query (platform resolver)"}), 200
    except network_tools.DnsError as e:
        return jsonify({"name": name, "qtype": qtype, "records": [],
                        "provenance": "UNAVAILABLE", "source": "DNS query (platform resolver)",
                        "note": str(e)}), 200


@wb.route("/api/wb/network/rdns", methods=["POST"])
@security.api_login_required
def net_rdns():
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()
    if not ioc_engine.is_ipv4(ip) and not ioc_engine.is_ipv6(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    recs = network_tools.reverse_dns(ip)
    return jsonify({"ip": ip, "records": recs,
                    "provenance": "OBSERVED" if recs else "UNAVAILABLE",
                    "source": "reverse DNS (OS resolver)"}), 200


# --- file analysis ---

@wb.route("/api/wb/files", methods=["POST"])
@security.api_login_required
def upload_file():
    fh = request.files.get("file")
    if not fh or not fh.filename:
        return jsonify({"error": "No file provided (multipart field 'file')."}), 400
    original = file_analysis.secure_filename_local(fh.filename)
    if not file_analysis.allowed_extension(original):
        return jsonify({"error": f"File type not allowed. Allowed: "
                                 f"{', '.join(sorted(config.ALLOWED_UPLOAD_EXTENSIONS))}"}), 400
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    stored = file_analysis.stored_name_for(original)
    path = os.path.join(config.UPLOAD_DIR, stored)
    written = 0
    with open(path, "wb") as out:
        while True:
            chunk = fh.stream.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > config.MAX_UPLOAD_BYTES:
                out.close()
                os.remove(path)
                return jsonify({"error": f"File exceeds maximum size "
                                         f"({config.MAX_UPLOAD_BYTES} bytes)."}), 413
            out.write(chunk)
    if written == 0:
        os.remove(path)
        return jsonify({"error": "Empty file rejected."}), 400

    analysis = file_analysis.analyze_file(path, original)
    fid = platform_db.save_uploaded_file(stored, original, written, analysis,
                                         kind=analysis["kind"], analyst=security.current_user())
    security.audit_event("file_upload", f"{original} sha256={analysis['sha256']}")
    return jsonify({"file_id": fid, "stored_name": stored, "analysis": analysis}), 200


@wb.route("/api/wb/files", methods=["GET"])
@security.api_login_required
def list_files():
    return jsonify({"files": platform_db.recent_files(limit=100, demo=0)}), 200


@wb.route("/api/wb/files/<int:fid>", methods=["GET"])
@security.api_login_required
def get_file(fid):
    rec = platform_db.get_uploaded_file(fid)
    if not rec:
        return jsonify({"error": "File not found"}), 404
    path = os.path.join(config.UPLOAD_DIR, rec["stored_name"])
    if not os.path.exists(path):
        return jsonify({"record": rec, "analysis": None,
                        "note": "Stored bytes no longer present on disk."}), 200
    return jsonify({"record": rec, "analysis": file_analysis.analyze_file(path, rec["original_name"])}), 200


# --- log analysis ---

@wb.route("/api/wb/logs", methods=["POST"])
@security.api_login_required
def upload_log():
    fh = request.files.get("file")
    if not fh or not fh.filename:
        return jsonify({"error": "No file provided (multipart field 'file')."}), 400
    original = file_analysis.secure_filename_local(fh.filename)
    if os.path.splitext(original)[1].lower() not in (".txt", ".log", ".csv", ".json"):
        return jsonify({"error": "Log uploads must be .txt, .log, .csv or .json"}), 400
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    stored = "log_" + file_analysis.stored_name_for(original)
    path = os.path.join(config.UPLOAD_DIR, stored)
    written = 0
    with open(path, "wb") as out:
        while True:
            chunk = fh.stream.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > config.MAX_LOG_BYTES:
                out.close()
                os.remove(path)
                return jsonify({"error": "Log exceeds maximum size."}), 413
            out.write(chunk)
    summary = log_analysis.analyze(path)
    lid = platform_db.save_log_job(stored, original, written,
                                   summary["overview"]["total_events"], analyst=security.current_user())
    security.audit_event("log_upload", f"{original} events={summary['overview']['total_events']}")
    return jsonify({"log_id": lid, "stored_name": stored, "summary": summary}), 200


@wb.route("/api/wb/logs", methods=["GET"])
@security.api_login_required
def list_logs():
    return jsonify({"logs": platform_db.recent_log_jobs(limit=100, demo=0)}), 200


def _log_path(lid):
    rec = platform_db.get_log_job(lid)
    if not rec:
        return None, None
    return rec, os.path.join(config.UPLOAD_DIR, rec["stored_name"])


@wb.route("/api/wb/logs/<int:lid>/summary", methods=["GET"])
@security.api_login_required
def log_summary(lid):
    rec, path = _log_path(lid)
    if not rec or not os.path.exists(path):
        return jsonify({"error": "Log not found on disk"}), 404
    return jsonify({"record": rec, "summary": log_analysis.analyze(path)}), 200


@wb.route("/api/wb/logs/<int:lid>/search", methods=["POST"])
@security.api_login_required
def log_search(lid):
    rec, path = _log_path(lid)
    if not rec or not os.path.exists(path):
        return jsonify({"error": "Log not found on disk"}), 404
    p = request.get_json(silent=True) or {}
    result = log_analysis.search(
        path,
        keyword=p.get("keyword"),
        regex=p.get("regex"),
        ip=p.get("ip"),
        severity=p.get("severity"),
        event_type=p.get("event_type"),
        start=p.get("start"),
        end=p.get("end"),
        limit=int(p.get("limit", 200)),
    )
    return jsonify(result), 200


# --- cases ---

def _next_case_id() -> str:
    year = datetime.now().year
    existing = platform_db.list_cases(demo=0) + platform_db.list_cases(demo=1)
    nums = []
    for c in existing:
        m = re.match(rf"CASE-{year}-(\d+)$", c["case_id"])
        if m:
            nums.append(int(m.group(1)))
    return f"CASE-{year}-{(max(nums) + 1) if nums else 1:04d}"


@wb.route("/api/wb/cases", methods=["POST"])
@security.api_login_required
def create_case():
    p = request.get_json(silent=True) or {}
    title = (p.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400
    case_id = _next_case_id()
    db_id = platform_db.create_case(case_id, title, p.get("description", ""),
                                    analyst=security.current_user(),
                                    priority=(p.get("priority") or "MEDIUM").upper())
    platform_db.add_timeline(db_id, "case", f"Case {case_id} created", "USER-PROVIDED", "analyst")
    security.audit_event("case_create", case_id)
    return jsonify({"case_id": case_id, "db_id": db_id}), 200


@wb.route("/api/wb/cases", methods=["GET"])
@security.api_login_required
def list_cases():
    return jsonify({"cases": platform_db.list_cases(demo=0)}), 200


@wb.route("/api/wb/cases/<int:db_id>", methods=["GET"])
@security.api_login_required
def get_case(db_id):
    case = platform_db.get_case(db_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({
        "case": case,
        "items": platform_db.case_items(db_id),
        "notes": platform_db.case_notes(db_id),
        "timeline": platform_db.case_timeline(db_id),
    }), 200


@wb.route("/api/wb/cases/<int:db_id>/items", methods=["POST"])
@security.api_login_required
def add_item(db_id):
    if not platform_db.get_case(db_id):
        return jsonify({"error": "Case not found"}), 404
    p = request.get_json(silent=True) or {}
    item_type = (p.get("item_type") or "").strip()
    item_ref = (p.get("item_ref") or "").strip()
    if not item_type or not item_ref:
        return jsonify({"error": "item_type and item_ref are required"}), 400
    platform_db.add_case_item(db_id, item_type, item_ref,
                              label=p.get("label", item_ref),
                              provenance=p.get("provenance", "USER-PROVIDED"),
                              added_by=security.current_user())
    platform_db.add_timeline(db_id, "evidence", f"Attached {item_type}: {item_ref}",
                             p.get("provenance", "USER-PROVIDED"), "analyst")
    security.audit_event("case_attach", f"case={db_id} {item_type}:{item_ref}")
    return jsonify({"added": True}), 200


@wb.route("/api/wb/cases/<int:db_id>/notes", methods=["POST"])
@security.api_login_required
def add_note(db_id):
    if not platform_db.get_case(db_id):
        return jsonify({"error": "Case not found"}), 404
    p = request.get_json(silent=True) or {}
    body = (p.get("body") or "").strip()
    if not body:
        return jsonify({"error": "body is required"}), 400
    platform_db.add_case_note(db_id, security.current_user(), body)
    platform_db.add_timeline(db_id, "note", "Analyst added note", "USER-PROVIDED", "analyst")
    security.audit_event("case_note", f"case={db_id}")
    return jsonify({"added": True}), 200


@wb.route("/api/wb/cases/<int:db_id>/status", methods=["POST"])
@security.api_login_required
def set_case_status(db_id):
    if not platform_db.get_case(db_id):
        return jsonify({"error": "Case not found"}), 404
    p = request.get_json(silent=True) or {}
    status = (p.get("status") or "").upper()
    if status not in ("OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"):
        return jsonify({"error": "status must be OPEN|IN_PROGRESS|RESOLVED|CLOSED"}), 400
    platform_db.update_case(db_id, status=status)
    platform_db.add_timeline(db_id, "case", f"Case status set to {status}", "USER-PROVIDED", "analyst")
    return jsonify({"status": status}), 200


@wb.route("/api/wb/cases/<int:db_id>/timeline", methods=["GET"])
@security.api_login_required
def case_timeline(db_id):
    return jsonify({"timeline": platform_db.case_timeline(db_id)}), 200


# --- reports ---

@wb.route("/api/wb/cases/<int:db_id>/report", methods=["POST"])
@security.api_login_required
def case_report(db_id):
    p = request.get_json(silent=True) or {}
    fmt = (p.get("format") or "pdf").lower()
    out = reports.generate(db_id, fmt, analyst=security.current_user())
    if "error" in out:
        return jsonify({"error": out["error"]}), 404
    platform_db.add_timeline(db_id, "report", f"Generated {fmt.upper()} report {out['stored_name']}",
                             "CALCULATED", "report generator")
    security.audit_event("report_generate", f"case={db_id} fmt={fmt} file={out['stored_name']}")
    return jsonify({"stored_name": out["stored_name"], "format": out["format"],
                    "download_url": f"/api/wb/reports/download/{out['stored_name']}"}), 200


@wb.route("/api/wb/reports", methods=["GET"])
@security.api_login_required
def list_reports():
    return jsonify({"reports": platform_db.recent_reports(limit=100)}), 200


@wb.route("/api/wb/reports/download/<path:stored_name>", methods=["GET"])
@security.api_login_required
def download_report(stored_name):
    safe = os.path.basename(stored_name)
    path = os.path.join(config.REPORT_DIR, safe)
    if not os.path.exists(path):
        return jsonify({"error": "Report not found"}), 404
    security.audit_event("report_download", safe)
    return send_from_directory(config.REPORT_DIR, safe, as_attachment=True)


# --- providers / demo / audit ---

@wb.route("/api/wb/providers", methods=["GET"])
@security.api_login_required
def provider_status():
    return jsonify({"providers": providers.provider_statuses()}), 200


@wb.route("/api/wb/demo", methods=["GET"])
@security.api_login_required
def demo_bundle():
    return jsonify(demo_data.demo_bundle()), 200


@wb.route("/api/wb/demo/seed", methods=["POST"])
@security.api_login_required
def demo_seed():
    out = demo_data.seed_demo()
    security.audit_event("demo_seed", str(out))
    return jsonify(out), 200


@wb.route("/api/wb/demo/cases", methods=["GET"])
@security.api_login_required
def demo_cases():
    return jsonify({"cases": platform_db.list_cases(demo=1)}), 200


@wb.route("/api/wb/audit", methods=["GET"])
@security.api_login_required
def audit_view():
    return jsonify({"audit": platform_db.recent_audit(limit=200)}), 200
