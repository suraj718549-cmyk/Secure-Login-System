"""
Session management: timeout enforcement and activity tracking.
"""
from datetime import datetime, timedelta
from flask import session, redirect, url_for, flash, request


def enforce_session_timeout():
    """Check session expiry on each request for authenticated users."""
    from flask import current_app

    # Skip for static files and unauthenticated routes
    if not session.get("user_id"):
        return None

    # Skip logout and login routes
    if request.endpoint in ("auth.logout", "auth.login", "static"):
        return None

    last_activity = session.get("last_activity")
    timeout_minutes = current_app.config.get("SESSION_TIMEOUT_MINUTES", 30)

    if last_activity:
        try:
            last_time = datetime.fromisoformat(last_activity)
            if datetime.utcnow() - last_time > timedelta(minutes=timeout_minutes):
                session.clear()
                flash("Session expired due to inactivity. Please log in again.", "warning")
                return redirect(url_for("auth.login"))
        except (ValueError, TypeError):
            pass

    # Update last activity timestamp
    session["last_activity"] = datetime.utcnow().isoformat()
    session.modified = True
    return None


def init_session(user):
    """Initialize session data after successful authentication."""
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["email"] = user["email"]
    session["is_admin"] = bool(user["is_admin"])
    session["totp_enabled"] = bool(user["totp_enabled"])
    session["last_activity"] = datetime.utcnow().isoformat()
    session["authenticated"] = True
