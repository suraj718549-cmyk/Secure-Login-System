"""
Entry point for the Secure Login System.
Run: python run.py
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    print("=" * 60)
    print("  SECURE LOGIN SYSTEM — Cybersecurity Portal")
    print("=" * 60)
    print("  URL: http://127.0.0.1:5000")
    print("  Default admin: admin / Admin@123")
    print("  Change credentials after first login!")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
