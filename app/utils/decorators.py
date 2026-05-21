"""
Route decorators for login-required and admin-only access.
"""
from functools import wraps
from flask import session, redirect, url_for, flash


def login_required(f):
    """Ensure user is authenticated before accessing route."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """Ensure user is an administrator."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        if not session.get("is_admin"):
            flash("Administrator access required.", "danger")
            return redirect(url_for("main.dashboard"))
        return f(*args, **kwargs)

    return decorated
