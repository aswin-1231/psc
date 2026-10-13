"""
Application Configuration for PassGuard Cyber Security Suite.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Secret Key for Flask sessions, signing cookies, and CSRF
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()

    # Pepper for zero-knowledge password HMAC calculation
    PEPPER = os.environ.get("PEPPER") or os.urandom(32).hex()

    # Anthropic API Key
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    # Database: SQLite in app root
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'passguard.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session Management: 30-minute inactivity expiration
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour validity

    # Request limits (defense against payload inflation attacks)
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 Megabytes
