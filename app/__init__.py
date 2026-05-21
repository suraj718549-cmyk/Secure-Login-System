"""
Flask application factory for the Secure Login System.
"""
import os
from flask import Flask

from config import Config
from app.database import init_db


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )
    app.config.from_object(config_class)

    # Ensure instance folder exists for SQLite database
    os.makedirs(os.path.dirname(app.config["DATABASE_PATH"]), exist_ok=True)

    # Initialize database schema
    init_db(app.config["DATABASE_PATH"])

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.main.routes import main_bp
    from app.admin.routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)

    # Session timeout middleware
    @app.before_request
    def check_session_timeout():
        from app.utils.session_manager import enforce_session_timeout
        enforce_session_timeout()

    return app
