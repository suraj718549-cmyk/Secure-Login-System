"""
Admin dashboard routes for user and activity monitoring.
"""
from flask import Blueprint, render_template, session

from app import database as db
from app.utils.decorators import admin_required
from app.utils.helpers import get_db_path

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@admin_required
def dashboard():
    """Administrator security operations center view."""
    db_path = get_db_path()
    users = db.get_all_users(db_path)
    logs = db.get_all_activity_logs(db_path, limit=50)

    stats = {
        "total_users": len(users),
        "admin_users": sum(1 for u in users if u["is_admin"]),
        "users_with_2fa": sum(1 for u in users if u["totp_enabled"]),
        "recent_failures": sum(
            1 for log in logs
            if log["status"] == "FAILURE"
        ),
    }

    return render_template(
        "admin.html",
        users=users,
        logs=logs,
        stats=stats,
    )
