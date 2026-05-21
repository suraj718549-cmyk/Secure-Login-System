"""
Input validation and sanitization for authentication forms.
"""
import re
import html

# Allowed characters for usernames (alphanumeric + underscore, 3-20 chars)
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def sanitize_input(value):
    """Strip whitespace and escape HTML entities to prevent XSS."""
    if value is None:
        return ""
    value = str(value).strip()
    return html.escape(value)


def validate_username(username):
    """Validate username format."""
    username = sanitize_input(username)
    if not USERNAME_PATTERN.match(username):
        return None, "Username must be 3-20 characters (letters, numbers, underscore only)."
    return username, None


def validate_email(email):
    """Validate email format."""
    email = sanitize_input(email).lower()
    if not email or len(email) > 254:
        return None, "Invalid email address."
    if not EMAIL_PATTERN.match(email):
        return None, "Invalid email format."
    return email, None


def validate_password(password, min_length=8):
    """
    Validate password strength.
    Requires: min length, uppercase, lowercase, digit, special char.
    """
    if not password:
        return "Password is required."
    if len(password) < min_length:
        return f"Password must be at least {min_length} characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return None


def validate_password_match(password, confirm):
    """Ensure password confirmation matches."""
    if password != confirm:
        return "Passwords do not match."
    return None
