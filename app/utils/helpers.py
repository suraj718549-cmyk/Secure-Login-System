"""
Helper functions for templates and request handling.
"""
from flask import session, current_app
from app.auth.security import generate_csrf_token


def get_client_ip(request):
    """Extract client IP address from request (proxy-aware)."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "unknown"


def set_csrf_token():
    """Generate and store CSRF token in session."""
    token = generate_csrf_token()
    session["csrf_token"] = token
    return token


def get_csrf_token():
    """
    Return CSRF token for forms.
    On GET: generate a new token. On POST: use existing token (do not rotate before validation).
    """
    from flask import request
    if request.method == "GET" or "csrf_token" not in session:
        return set_csrf_token()
    return session["csrf_token"]


def get_db_path():
    """Return configured database path."""
    return current_app.config["DATABASE_PATH"]
