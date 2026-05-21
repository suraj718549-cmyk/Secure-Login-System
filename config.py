"""
Application configuration for the Secure Login System.
Override SECRET_KEY in production via environment variable.
"""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration with security-focused defaults."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-this-in-production-2024!")
    DATABASE_PATH = os.path.join(BASE_DIR, "instance", "secure_auth.db")

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_TIMEOUT_MINUTES = 30

    # Login attempt limits
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15

    # Password policy
    MIN_PASSWORD_LENGTH = 8

    # CSRF token lifetime (seconds)
    CSRF_TOKEN_LIFETIME = 3600

    # Password reset token expiry (hours)
    RESET_TOKEN_HOURS = 1
