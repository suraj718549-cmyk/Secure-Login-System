"""
Main routes: dashboard and user profile features.
"""
from flask import Blueprint, render_template, session, flash, redirect, url_for, request

from app import database as db
from app.utils.decorators import login_required
from app.utils.helpers import get_db_path, set_csrf_token, get_client_ip
from app.auth.security import validate_csrf, hash_password, verify_password
from app.auth.validators import validate_password, validate_password_match

main_bp = Blueprint("main", __name__)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    """User security dashboard with activity logs."""
    db_path = get_db_path()
    user = db.get_user_by_id(db_path, session["user_id"])
    logs = db.get_user_activity_logs(db_path, session["user_id"], limit=20)

    stats = {
        "total_logins": sum(1 for log in logs if log["action"] == "LOGIN" and log["status"] == "SUCCESS"),
        "failed_attempts": user["failed_attempts"] or 0,
        "totp_enabled": bool(user["totp_enabled"]),
        "last_login": user["last_login"] or "Never",
        "member_since": user["created_at"][:10] if user["created_at"] else "N/A",
    }

    return render_template(
        "dashboard.html",
        user=user,
        logs=logs,
        stats=stats,
    )


@main_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow authenticated users to change their password."""
    if request.method == "GET":
        csrf_token = set_csrf_token()
    else:
        csrf_token = session.get("csrf_token", "")

    if request.method == "POST":
        if not validate_csrf(session, request.form.get("csrf_token")):
            flash("Invalid security token.", "danger")
            return redirect(url_for("main.change_password"))

        current = request.form.get("current_password", "")
        new_pass = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        db_path = get_db_path()
        user = db.get_user_by_id(db_path, session["user_id"])

        if not verify_password(current, user["password_hash"]):
            flash("Current password is incorrect.", "danger")
        else:
            pwd_err = validate_password(new_pass)
            match_err = validate_password_match(new_pass, confirm)
            if pwd_err:
                flash(pwd_err, "danger")
            elif match_err:
                flash(match_err, "danger")
            else:
                db.update_password(db_path, user["id"], hash_password(new_pass))
                db.log_activity(
                    db_path, user["id"], user["username"], "PASSWORD_CHANGE",
                    "SUCCESS", get_client_ip(request), "Password updated",
                )
                flash("Password changed successfully.", "success")
                return redirect(url_for("main.dashboard"))

    return render_template("change_password.html", csrf_token=csrf_token)
