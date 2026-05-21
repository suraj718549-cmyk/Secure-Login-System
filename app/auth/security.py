"""
Security utilities: password hashing, CSRF tokens, account lockout checks.
"""
import hashlib
import secrets
from datetime import datetime

import bcrypt


def hash_password(password: str) -> str:
    """Hash password using bcrypt with cost factor 12."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def generate_csrf_token():
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def validate_csrf(session, form_token):
    """Validate CSRF token from form against session."""
    stored = session.get("csrf_token")
    if not stored or not form_token:
        return False
    return secrets.compare_digest(stored, form_token)


def is_account_locked(user):
    """Check if user account is temporarily locked due to failed attempts."""
    locked_until = user["locked_until"]
    if not locked_until:
        return False, None
    try:
        lock_time = datetime.fromisoformat(locked_until)
        if datetime.utcnow() < lock_time:
            remaining = int((lock_time - datetime.utcnow()).total_seconds() / 60) + 1
            return True, remaining
    except (ValueError, TypeError):
        pass
    return False, None


def generate_reset_token():
    """Generate secure password reset token."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Hash token for secure storage in database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
