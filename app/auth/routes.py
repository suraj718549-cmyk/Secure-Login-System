"""
Authentication routes: register, login, logout, 2FA, password reset.
"""
from datetime import datetime, timedelta

import pyotp
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app,
)

from app import database as db
from app.auth.validators import (
    sanitize_input, validate_username, validate_email,
    validate_password, validate_password_match,
)
from app.auth.security import (
    hash_password, verify_password, validate_csrf,
    is_account_locked, generate_reset_token, hash_token,
)
from app.utils.helpers import get_client_ip, set_csrf_token, get_csrf_token, get_db_path
from app.utils.session_manager import init_session

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    """Redirect root to login or dashboard."""
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """User registration with validation and secure password storage."""
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))

    if request.method == "GET":
        csrf_token = set_csrf_token()
    else:
        csrf_token = session.get("csrf_token", "")

    if request.method == "POST":
        if not validate_csrf(session, request.form.get("csrf_token")):
            flash("Invalid security token. Please try again.", "danger")
            return render_template("register.html", csrf_token=set_csrf_token())

        username, err = validate_username(request.form.get("username", ""))
        email, err2 = validate_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if err:
            flash(err, "danger")
        elif err2:
            flash(err2, "danger")
        else:
            pwd_err = validate_password(
                password, current_app.config["MIN_PASSWORD_LENGTH"]
            )
            match_err = validate_password_match(password, confirm)

            if pwd_err:
                flash(pwd_err, "danger")
            elif match_err:
                flash(match_err, "danger")
            else:
                db_path = get_db_path()
                if db.get_user_by_username(db_path, username):
                    flash("Username already exists.", "danger")
                elif db.get_user_by_email(db_path, email):
                    flash("Email already registered.", "danger")
                else:
                    password_hash = hash_password(password)
                    user_id = db.create_user(db_path, username, email, password_hash)
                    db.log_activity(
                        db_path, user_id, username, "REGISTER",
                        "SUCCESS", get_client_ip(request),
                        "New account created",
                    )
                    flash("Registration successful! Please log in.", "success")
                    return redirect(url_for("auth.login"))

    return render_template("register.html", csrf_token=csrf_token)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Secure login with attempt limiting and optional 2FA."""
    if session.get("user_id") and session.get("authenticated"):
        return redirect(url_for("main.dashboard"))

    if request.method == "GET":
        csrf_token = set_csrf_token()
    else:
        csrf_token = session.get("csrf_token", "")

    if request.method == "POST":
        if not validate_csrf(session, request.form.get("csrf_token")):
            flash("Invalid security token. Please try again.", "danger")
            return render_template("login.html", csrf_token=set_csrf_token())

        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html", csrf_token=csrf_token)

        db_path = get_db_path()
        user = db.get_user_by_username(db_path, username)

        if not user:
            # Generic message to prevent user enumeration
            flash("Invalid username or password.", "danger")
            db.log_activity(
                db_path, None, username, "LOGIN",
                "FAILURE", get_client_ip(request), "User not found",
            )
            return render_template("login.html", csrf_token=csrf_token)

        locked, minutes = is_account_locked(user)
        if locked:
            flash(
                f"Account locked. Try again in {minutes} minute(s).",
                "danger",
            )
            return render_template("login.html", csrf_token=csrf_token)

        if not verify_password(password, user["password_hash"]):
            attempts, _ = db.increment_failed_attempts(
                db_path, user["id"],
                current_app.config["MAX_LOGIN_ATTEMPTS"],
                current_app.config["LOCKOUT_MINUTES"],
            )
            remaining = current_app.config["MAX_LOGIN_ATTEMPTS"] - attempts
            msg = "Invalid username or password."
            if remaining > 0:
                msg += f" {remaining} attempt(s) remaining."
            else:
                msg += f" Account locked for {current_app.config['LOCKOUT_MINUTES']} minutes."
            flash(msg, "danger")
            db.log_activity(
                db_path, user["id"], username, "LOGIN",
                "FAILURE", get_client_ip(request), "Invalid password",
            )
            return render_template("login.html", csrf_token=csrf_token)

        # Password correct — check 2FA if enabled
        if user["totp_enabled"]:
            session["pending_2fa_user_id"] = user["id"]
            session["pending_2fa_username"] = user["username"]
            return redirect(url_for("auth.verify_2fa"))

        db.update_login_success(db_path, user["id"])
        init_session(user)
        db.log_activity(
            db_path, user["id"], username, "LOGIN",
            "SUCCESS", get_client_ip(request), "Authenticated",
        )
        flash("Access granted. Welcome to the secure portal.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("login.html", csrf_token=csrf_token)


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """Verify TOTP code for two-factor authentication."""
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        csrf_token = set_csrf_token()
    else:
        csrf_token = session.get("csrf_token", "")

    db_path = get_db_path()
    user = db.get_user_by_id(db_path, user_id)

    if not user or not user["totp_enabled"]:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        if not validate_csrf(session, request.form.get("csrf_token")):
            flash("Invalid security token.", "danger")
            return render_template("verify_2fa.html", csrf_token=set_csrf_token())

        code = sanitize_input(request.form.get("totp_code", ""))
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code, valid_window=1):
            session.pop("pending_2fa_user_id", None)
            session.pop("pending_2fa_username", None)
            db.update_login_success(db_path, user["id"])
            init_session(user)
            db.log_activity(
                db_path, user["id"], user["username"], "LOGIN_2FA",
                "SUCCESS", get_client_ip(request), "2FA verified",
            )
            flash("Two-factor authentication successful.", "success")
            return redirect(url_for("main.dashboard"))

        flash("Invalid authentication code.", "danger")
        db.log_activity(
            db_path, user["id"], user["username"], "LOGIN_2FA",
            "FAILURE", get_client_ip(request), "Invalid TOTP",
        )

    return render_template("verify_2fa.html", csrf_token=csrf_token)


@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    """Enable two-factor authentication for current user."""
    from app.utils.decorators import login_required

    if not session.get("user_id"):
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        csrf_token = set_csrf_token()
    else:
        csrf_token = session.get("csrf_token", "")

    db_path = get_db_path()
    user = db.get_user_by_id(db_path, session["user_id"])

    if user["totp_enabled"]:
        flash("2FA is already enabled on your account.", "info")
        return redirect(url_for("main.dashboard"))

    # Generate secret on first visit
    if "setup_totp_secret" not in session:
        session["setup_totp_secret"] = pyotp.random_base32()

    secret = session["setup_totp_secret"]
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user["email"],
        issuer_name="SecureLogin SOC",
    )

    if request.method == "POST":
        if not validate_csrf(session, request.form.get("csrf_token")):
            flash("Invalid security token.", "danger")
            return redirect(url_for("auth.setup_2fa"))

        code = sanitize_input(request.form.get("totp_code", ""))
        if totp.verify(code, valid_window=1):
            db.enable_2fa(db_path, user["id"], secret)
            session.pop("setup_totp_secret", None)
            session["totp_enabled"] = True
            db.log_activity(
                db_path, user["id"], user["username"], "2FA_ENABLE",
                "SUCCESS", get_client_ip(request), "2FA activated",
            )
            flash("Two-factor authentication enabled successfully.", "success")
            return redirect(url_for("main.dashboard"))

        flash("Invalid code. Please scan the QR and try again.", "danger")

    return render_template(
        "setup_2fa.html",
        csrf_token=csrf_token,
        secret=secret,
        provisioning_uri=provisioning_uri,
    )


@auth_bp.route("/logout")
def logout():
    """Clear session and log logout activity."""
    db_path = get_db_path()
    if session.get("user_id"):
        db.log_activity(
            db_path, session["user_id"], session.get("username"),
            "LOGOUT", "SUCCESS", get_client_ip(request), "Session ended",
        )
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Request password reset token (displayed for demo; use email in production)."""
    if request.method == "GET":
        csrf_token = set_csrf_token()
    else:
        csrf_token = session.get("csrf_token", "")

    if request.method == "POST":
        if not validate_csrf(session, request.form.get("csrf_token")):
            flash("Invalid security token.", "danger")
            return render_template("forgot_password.html", csrf_token=set_csrf_token())

        email, err = validate_email(request.form.get("email", ""))
        if err:
            flash(err, "danger")
        else:
            db_path = get_db_path()
            user = db.get_user_by_email(db_path, email)
            # Always show same message to prevent email enumeration
            if user:
                token = generate_reset_token()
                token_hash = hash_token(token)
                expires = (
                    datetime.utcnow()
                    + timedelta(hours=current_app.config["RESET_TOKEN_HOURS"])
                ).isoformat()
                db.save_reset_token(db_path, user["id"], token_hash, expires)
                db.log_activity(
                    db_path, user["id"], user["username"], "PASSWORD_RESET_REQUEST",
                    "SUCCESS", get_client_ip(request), "Reset token generated",
                )
                reset_url = url_for("auth.reset_password", token=token, _external=True)
                flash(
                    f"If that email exists, a reset link was generated. "
                    f"(Demo) Reset URL: {reset_url}",
                    "info",
                )
            else:
                flash(
                    "If that email is registered, you will receive reset instructions.",
                    "info",
                )
            return redirect(url_for("auth.login"))

    return render_template("forgot_password.html", csrf_token=csrf_token)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Reset password using secure token."""
    if request.method == "GET":
        csrf_token = set_csrf_token()
    else:
        csrf_token = session.get("csrf_token", "")

    db_path = get_db_path()
    token_hash = hash_token(token)
    reset_record = db.get_valid_reset_token(db_path, token_hash)

    if not reset_record:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        if not validate_csrf(session, request.form.get("csrf_token")):
            flash("Invalid security token.", "danger")
            return render_template("reset_password.html", csrf_token=set_csrf_token())

        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        pwd_err = validate_password(
            password, current_app.config["MIN_PASSWORD_LENGTH"]
        )
        match_err = validate_password_match(password, confirm)

        if pwd_err:
            flash(pwd_err, "danger")
        elif match_err:
            flash(match_err, "danger")
        else:
            password_hash = hash_password(password)
            db.update_password(db_path, reset_record["user_id"], password_hash)
            db.mark_reset_token_used(db_path, reset_record["id"])
            user = db.get_user_by_id(db_path, reset_record["user_id"])
            db.log_activity(
                db_path, user["id"], user["username"], "PASSWORD_RESET",
                "SUCCESS", get_client_ip(request), "Password changed",
            )
            flash("Password reset successful. Please log in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("reset_password.html", csrf_token=csrf_token)
