"""
High-performance top 10,000 common passwords validator.
Provides O(1) set-based lookups for breached and easily guessable passwords.
"""

from pathlib import Path
from typing import Set

_COMMON_PASSWORDS_SET: Set[str] = set()
_WORDLIST_PATH = Path(__file__).resolve().parent / "top_10000_passwords.txt"


def _load_common_passwords() -> Set[str]:
    global _COMMON_PASSWORDS_SET
    if _COMMON_PASSWORDS_SET:
        return _COMMON_PASSWORDS_SET

    if not _WORDLIST_PATH.exists():
        # Fallback basic list if file is somehow missing
        fallback = {
            "password", "123456", "12345678", "qwerty", "admin", "letmein",
            "welcome", "secret", "abc123", "password123", "iloveyou"
        }
        _COMMON_PASSWORDS_SET = fallback
        return _COMMON_PASSWORDS_SET

    with open(_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip().lower()
            if word:
                _COMMON_PASSWORDS_SET.add(word)

    return _COMMON_PASSWORDS_SET


def is_common_password(password: str) -> bool:
    """
    Check if a given password matches any known top common passwords.
    Checks exact match and normalized lowercase match.
    """
    if not password:
        return False

    passwords_set = _load_common_passwords()
    normalized = password.strip().lower()
    return normalized in passwords_set or password.strip() in passwords_set


# Pre-load on import for instant subsequent requests
_load_common_passwords()
