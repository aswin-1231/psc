"""
Cryptographic hashing and zero-knowledge HMAC utilities.
Guarantees that plain-text passwords are never stored, logged, or serialized.
"""

import hashlib
import hmac
import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger(__name__)

# Argon2id password hasher with recommended OWASP parameters
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16
)


def hash_password(plain_password: str) -> str:
    """Hash an account password using Argon2id."""
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    return _ph.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify an account password against an Argon2id hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as e:
        logger.error(f"Unexpected error during password verification: {e}")
        return False


def generate_password_hmac(plain_password: str, user_id: int, pepper: str) -> str:
    """
    Generate a zero-knowledge HMAC-SHA256 for password reuse detection.
    The HMAC key is derived from the server-side PEPPER and user_id.
    The resulting hash cannot be reversed or cross-correlated across users.
    """
    if not pepper:
        raise ValueError("PEPPER must be configured for password HMAC generation.")
    
    # Derive user-isolated key using pepper
    derived_key = hmac.new(
        pepper.encode("utf-8"),
        str(user_id).encode("utf-8"),
        hashlib.sha256
    ).digest()

    # Calculate HMAC of the tested password
    return hmac.new(
        derived_key,
        plain_password.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def mask_password(plain_password: str) -> str:
    """
    Produce a sanitized, non-reversible visual mask of a password for history display.
    Examples:
      'Password123!' -> 'P••••••••••!'
      'secret'       -> 's••••t'
      'ab'           -> '••'
    """
    length = len(plain_password)
    if length <= 2:
        return "•" * length
    first = plain_password[0]
    last = plain_password[-1]
    dots = "•" * (length - 2)
    return f"{first}{dots}{last}"
