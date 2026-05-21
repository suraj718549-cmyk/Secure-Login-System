# Secure Login System

A professional, cybersecurity-themed authentication web application built with Python and Flask. Features a futuristic SOC-style portal UI with strong security practices suitable for portfolios and learning.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![Security](https://img.shields.io/badge/Security-bcrypt%20%7C%20CSRF%20%7C%202FA-cyan)

## Features

### Core Authentication
- User registration with validation
- Secure login with bcrypt password hashing
- Session management with 30-minute timeout
- Logout functionality
- Password visibility toggle
- Error handling for invalid credentials

### Security
- **bcrypt** password hashing (cost factor 12)
- **Parameterized SQL** queries (SQL injection protection)
- **Input validation & sanitization** (XSS prevention)
- **CSRF token** protection on all forms
- **Account lockout** after 5 failed login attempts (15 min)
- **Session timeout** on inactivity
- **Two-Factor Authentication (2FA)** via TOTP (Google Authenticator)
- **Password reset** with secure time-limited tokens

### UI/UX
- Cyberpunk / SOC cybersecurity dashboard theme
- Neon blue-green aesthetic with matrix rain animation
- Responsive dark-themed design (Bootstrap 5)
- Animated login with loading states
- Login success/failure notifications
- Hacker-style loading animations

### Extra
- User activity logs
- Admin SOC dashboard
- SQLite database integration

## Project Structure

```
Secure-Login-System/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── database.py          # SQLite + prepared statements
│   ├── auth/
│   │   ├── routes.py        # Login, register, 2FA, reset
│   │   ├── security.py      # Hashing, CSRF, lockout
│   │   └── validators.py    # Input validation
│   ├── main/
│   │   └── routes.py        # Dashboard, change password
│   ├── admin/
│   │   └── routes.py        # Admin SOC panel
│   └── utils/
│       ├── decorators.py    # login_required, admin_required
│       ├── session_manager.py
│       └── helpers.py
├── static/
│   ├── css/style.css        # Cyberpunk theme
│   └── js/                  # Matrix animation, UI logic
├── templates/               # Jinja2 HTML templates
├── instance/                # SQLite database (auto-created)
├── config.py
├── run.py
├── requirements.txt
└── README.md
```

## Quick Start

### Prerequisites
- Python 3.10 or higher
- pip

### Installation

```bash
# Clone or navigate to the project folder
cd Secure-Login-System

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py
```

Open your browser at: **http://127.0.0.1:5000**

### Default Admin Account

| Field    | Value        |
|----------|--------------|
| Username | `admin`      |
| Password | `Admin@123`  |

> Change the default admin password after first login!

## Usage Guide

### Register a New User
1. Go to **Create account** on the login page
2. Enter username (3–20 chars, alphanumeric + underscore)
3. Enter email and a strong password (uppercase, lowercase, digit, special char)
4. Log in with your new credentials

### Enable Two-Factor Authentication
1. Log in and go to the **Dashboard**
2. Click **Enable 2FA**
3. Scan the QR code with Google Authenticator (or similar)
4. Enter the 6-digit code to confirm

### Password Reset
1. Click **Forgot password?** on the login page
2. Enter your registered email
3. In demo mode, the reset URL is shown in the flash message
4. In production, send this URL via email instead

### Admin Dashboard
- Log in as `admin` to access **Admin SOC** in the navigation bar
- View all users and system-wide activity logs

## Security Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Browser   │────▶│  Flask App   │────▶│  SQLite (safe)  │
│  (CSRF tok) │     │  Validators  │     │  Param queries  │
└─────────────┘     │  bcrypt hash │     └─────────────────┘
                    │  Sessions    │
                    │  2FA (TOTP)  │
                    └──────────────┘
```

| Threat              | Mitigation                          |
|---------------------|-------------------------------------|
| SQL Injection       | Parameterized queries (`?`)       |
| XSS                 | HTML escaping on input              |
| CSRF                | Session-bound tokens per form       |
| Weak passwords      | Strength policy + bcrypt hashing    |
| Brute force         | Account lockout after 5 failures    |
| Session hijacking   | HttpOnly cookies, timeout, logout   |
| Credential stuffing | Generic error messages              |

## Configuration

Edit `config.py` or set environment variables:

| Setting               | Default   | Description                    |
|-----------------------|-----------|--------------------------------|
| `SECRET_KEY`          | (dev key) | Flask session secret           |
| `SESSION_TIMEOUT_MINUTES` | 30    | Inactivity timeout             |
| `MAX_LOGIN_ATTEMPTS`  | 5         | Attempts before lockout          |
| `LOCKOUT_MINUTES`     | 15        | Lockout duration                 |
| `MIN_PASSWORD_LENGTH` | 8         | Minimum password length          |

**Production checklist:**
- Set `SECRET_KEY` environment variable to a strong random value
- Set `debug=False` in `run.py`
- Use HTTPS and set `SESSION_COOKIE_SECURE = True`
- Send password reset links via email (not flash messages)

## Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite
- **Security:** bcrypt, pyotp (2FA)
- **Frontend:** HTML, CSS, JavaScript, Bootstrap 5
- **Fonts:** Orbitron, Share Tech Mono

## License

This project is for educational and portfolio purposes. Use responsibly and follow ethical cybersecurity practices.

## Author

Built as a beginner-friendly yet professional secure authentication system demonstration.
