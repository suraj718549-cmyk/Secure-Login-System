"""
SQLite database layer with parameterized queries (SQL injection protection).
"""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta


def get_connection(db_path):
    """Return a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db(db_path):
    """Context manager for database connections."""
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path):
    """Create database tables if they do not exist."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                totp_secret TEXT,
                totp_enabled INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)

        # Activity logs for security auditing
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        # Password reset tokens
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        # Create default admin if no users exist
        cursor.execute("SELECT COUNT(*) as count FROM users")
        if cursor.fetchone()["count"] == 0:
            import bcrypt
            from datetime import datetime as dt

            admin_hash = bcrypt.hashpw(
                b"Admin@123", bcrypt.gensalt(rounds=12)
            ).decode("utf-8")
            now = dt.utcnow().isoformat()
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash, is_admin, created_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                ("admin", "admin@securelogin.local", admin_hash, now),
            )


# --- User queries (all use parameterized statements) ---

def get_user_by_username(db_path, username):
    with get_db(db_path) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()


def get_user_by_email(db_path, email):
    with get_db(db_path) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
            (email.lower(),),
        ).fetchone()


def get_user_by_id(db_path, user_id):
    with get_db(db_path) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def create_user(db_path, username, email, password_hash):
    now = datetime.utcnow().isoformat()
    with get_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, email.lower(), password_hash, now),
        )
        return cursor.lastrowid


def update_password(db_path, user_id, password_hash):
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id),
        )


def update_login_success(db_path, user_id):
    now = datetime.utcnow().isoformat()
    with get_db(db_path) as conn:
        conn.execute(
            """
            UPDATE users
            SET failed_attempts = 0, locked_until = NULL, last_login = ?
            WHERE id = ?
            """,
            (now, user_id),
        )


def increment_failed_attempts(db_path, user_id, max_attempts, lockout_minutes):
    with get_db(db_path) as conn:
        user = conn.execute(
            "SELECT failed_attempts FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        attempts = (user["failed_attempts"] or 0) + 1
        locked_until = None
        if attempts >= max_attempts:
            locked_until = (
                datetime.utcnow() + timedelta(minutes=lockout_minutes)
            ).isoformat()
        conn.execute(
            """
            UPDATE users SET failed_attempts = ?, locked_until = ?
            WHERE id = ?
            """,
            (attempts, locked_until, user_id),
        )
        return attempts, locked_until


def enable_2fa(db_path, user_id, totp_secret):
    with get_db(db_path) as conn:
        conn.execute(
            """
            UPDATE users SET totp_secret = ?, totp_enabled = 1
            WHERE id = ?
            """,
            (totp_secret, user_id),
        )


def disable_2fa(db_path, user_id):
    with get_db(db_path) as conn:
        conn.execute(
            """
            UPDATE users SET totp_secret = NULL, totp_enabled = 0
            WHERE id = ?
            """,
            (user_id,),
        )


def log_activity(db_path, user_id, username, action, status, ip_address, details=""):
    now = datetime.utcnow().isoformat()
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO activity_logs
            (user_id, username, action, status, ip_address, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, action, status, ip_address, details, now),
        )


def get_user_activity_logs(db_path, user_id, limit=50):
    with get_db(db_path) as conn:
        return conn.execute(
            """
            SELECT * FROM activity_logs
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()


def get_all_activity_logs(db_path, limit=100):
    with get_db(db_path) as conn:
        return conn.execute(
            """
            SELECT * FROM activity_logs
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_all_users(db_path):
    with get_db(db_path) as conn:
        return conn.execute(
            """
            SELECT id, username, email, is_admin, totp_enabled,
                   failed_attempts, created_at, last_login
            FROM users ORDER BY created_at DESC
            """
        ).fetchall()


def save_reset_token(db_path, user_id, token_hash, expires_at):
    with get_db(db_path) as conn:
        conn.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = ?",
            (user_id,),
        )
        conn.execute(
            """
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
            """,
            (user_id, token_hash, expires_at),
        )


def get_valid_reset_token(db_path, token_hash):
    now = datetime.utcnow().isoformat()
    with get_db(db_path) as conn:
        return conn.execute(
            """
            SELECT * FROM password_reset_tokens
            WHERE token_hash = ? AND used = 0 AND expires_at > ?
            """,
            (token_hash, now),
        ).fetchone()


def mark_reset_token_used(db_path, token_id):
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
            (token_id,),
        )
