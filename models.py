"""
SQLAlchemy Database Models for PassGuard.
Enforces strict zero-knowledge constraints: no plain-text passwords stored.
"""

from datetime import datetime, timezone, timedelta
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    lock_until = db.Column(db.DateTime, nullable=True)

    # Relationships
    checks = db.relationship("PasswordCheck", backref="user", cascade="all, delete-orphan", lazy="dynamic")
    chat_messages = db.relationship("ChatMessage", backref="user", cascade="all, delete-orphan", lazy="dynamic")

    @property
    def initials(self) -> str:
        parts = self.full_name.strip().split()
        if len(parts) >= 2:
            return f"{parts[0][0]}{parts[1][0]}".upper()
        elif parts:
            return parts[0][:2].upper()
        return "PG"

    def is_locked(self) -> bool:
        """Returns True if the account is currently locked out."""
        if self.lock_until is None:
            return False
        # Normalize comparison to timezone-aware UTC or naive
        now = datetime.now(timezone.utc)
        lock_dt = self.lock_until
        if lock_dt.tzinfo is None:
            now = datetime.utcnow()
        return lock_dt > now

    def record_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 5) -> None:
        """Increments failed logins and triggers lockout upon reaching threshold."""
        self.failed_login_count += 1
        if self.failed_login_count >= max_attempts:
            now = datetime.now(timezone.utc)
            self.lock_until = now + timedelta(minutes=lockout_minutes)

    def reset_failed_login(self) -> None:
        """Resets failed login counter and clears lock status."""
        self.failed_login_count = 0
        self.lock_until = None


class PasswordCheck(db.Model):
    __tablename__ = "password_checks"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    password_hmac = db.Column(db.String(64), nullable=False, index=True)
    masked_preview = db.Column(db.String(64), nullable=False)
    length = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    level = db.Column(db.String(20), nullable=False)  # 'weak', 'medium', 'strong'
    common_flag = db.Column(db.Boolean, default=False, nullable=False)
    reused_flag = db.Column(db.Boolean, default=False, nullable=False)
    breached_flag = db.Column(db.Boolean, default=False, nullable=False)
    checked_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "masked_preview": self.masked_preview,
            "length": self.length,
            "score": self.score,
            "level": self.level,
            "common_flag": self.common_flag,
            "reused_flag": self.reused_flag,
            "breached_flag": self.breached_flag,
            "checked_at": self.checked_at.strftime("%Y-%m-%d %H:%M:%S") if self.checked_at else ""
        }


class ChatMessage(db.Model):
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False)  # 'user' or 'assistant'
    content = db.Column(db.Text, nullable=False)  # Always sanitized & redacted
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "role": self.role,
            "content": self.content,
            "created_at": self.created_at.strftime("%H:%M") if self.created_at else ""
        }
