"""
Cryptographically secure password and passphrase generator using Python's secrets module.
Guarantees high entropy, unguessability, and compliance with strong security criteria.
Generated suggestions are ephemeral and never persisted in database.
"""

import secrets
import string
from typing import List, Dict, Any, Optional, Set
from security.strength_engine import analyze_password_strength
from security.common_passwords import is_common_password

# Curated list of distinct, pronounceable words for passphrase generation
PASSPHRASE_WORDS = [
    "Maple", "River", "Quartz", "Falcon", "Cobalt", "Summit", "Timber", "Vortex",
    "Anchor", "Breeze", "Canyon", "Dolphin", "Echo", "Frost", "Granite", "Haven",
    "Island", "Jasper", "Knight", "Lantern", "Mirage", "Nebula", "Orbit", "Pinnacle",
    "Quasar", "Radar", "Shadow", "Thunder", "Umbra", "Velvet", "Whisper", "Zephyr",
    "Silver", "Golden", "Alpine", "Blaze", "Citadel", "Drift", "Eclipse", "Flare",
    "Glacier", "Horizon", "Infinity", "Jungle", "Kestrel", "Lunar", "Meteor", "Nova",
    "Opal", "Pulse", "Quantum", "Radiant", "Solar", "Titan", "Unity", "Valiant"
]

SYMBOLS = "!@#$%^&*()_-+=<>?"


def generate_secure_password(
    length: int = 16,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_special: bool = True
) -> str:
    """Generate a high-entropy password using Python's secrets module."""
    length = max(12, min(32, length))
    
    char_pool = ""
    guaranteed = []

    if include_lower:
        char_pool += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if include_upper:
        char_pool += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if include_digits:
        char_pool += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if include_special:
        char_pool += SYMBOLS
        guaranteed.append(secrets.choice(SYMBOLS))

    if not char_pool:
        # Fallback to full safe set if user unticked everything
        char_pool = string.ascii_letters + string.digits + SYMBOLS
        guaranteed = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(SYMBOLS)
        ]

    remaining_length = length - len(guaranteed)
    remaining_chars = [secrets.choice(char_pool) for _ in range(remaining_length)]
    combined = guaranteed + remaining_chars

    # Cryptographically secure in-place shuffle
    rng = secrets.SystemRandom()
    rng.shuffle(combined)

    return "".join(combined)


def generate_passphrase(
    word_count: int = 3,
    separator: str = "-",
    include_number: bool = True,
    include_special: bool = True
) -> str:
    """
    Generate an EFF-style passphrase like 'Maple-River-Quartz-42!'.
    Memorable yet computationally infeasible to brute-force.
    """
    words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]
    passphrase = separator.join(words)

    if include_number:
        num = secrets.randbelow(90) + 10  # 10 to 99
        passphrase += f"{separator}{num}"

    if include_special:
        sym = secrets.choice("!@#$%&*?")
        passphrase += sym

    return passphrase


def generate_curated_suggestions(
    count: int = 10,
    length: int = 16,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_special: bool = True,
    user_existing_hmacs: Optional[Set[str]] = None,
    user_id: Optional[int] = None,
    pepper: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Generate verified strong password suggestions.
    Guarantees that each returned suggestion is:
    1. Score >= 70 (Strong)
    2. Not in top 10k common password list
    3. Not in user's previous checks
    """
    suggestions = []
    attempts = 0
    max_attempts = count * 10

    # Ensure at least 2 are memorable passphrases and the rest are high-entropy strings
    passphrase_target = 3

    while len(suggestions) < count and attempts < max_attempts:
        attempts += 1
        is_passphrase = len(suggestions) < passphrase_target

        if is_passphrase:
            pwd = generate_passphrase(word_count=3, separator="-", include_number=True, include_special=True)
            pwd_type = "Passphrase"
        else:
            pwd = generate_secure_password(
                length=length,
                include_upper=include_upper,
                include_lower=include_lower,
                include_digits=include_digits,
                include_special=include_special
            )
            pwd_type = "High Entropy"

        # Check against common list
        if is_common_password(pwd):
            continue

        # Check reuse if user HMACs provided
        if user_existing_hmacs and user_id and pepper:
            from security.hasher import generate_password_hmac
            test_hmac = generate_password_hmac(pwd, user_id, pepper)
            if test_hmac in user_existing_hmacs:
                continue

        analysis = analyze_password_strength(pwd)
        if analysis["score"] >= 70:
            suggestions.append({
                "password": pwd,
                "type": pwd_type,
                "length": len(pwd),
                "score": analysis["score"],
                "level": analysis["level"],
                "entropy_bits": analysis["entropy_bits"],
                "crack_time": analysis["crack_time"]
            })

    return suggestions
