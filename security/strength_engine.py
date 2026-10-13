"""
PassGuard Comprehensive Password Strength Scoring Engine.
Calculates 0-100 composite security score, entropy (bits), crack time,
detailed rule checklist, and penalty detection for patterns, sequences, and leaks.
"""

import math
import re
from typing import Dict, Any, List, Optional
from security.common_passwords import is_common_password

# Standard character set definitions
UPPER_REGEX = re.compile(r"[A-Z]")
LOWER_REGEX = re.compile(r"[a-z]")
DIGIT_REGEX = re.compile(r"\d")
SPECIAL_REGEX = re.compile(r'[!@#$%^&*(),.?":{}|<>_\-+=/\\[\]~`]')

KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty",
    "123456", "234567", "345678", "456789", "567890",
    "abcdef", "bcdefg", "cdefgh", "defghi", "password"
]

LEET_REPLACEMENTS = {
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i", "|": "i",
    "0": "o",
    "5": "s", "$": "s",
    "7": "t", "+": "t",
    "8": "b",
}


def get_criteria_state(password: str) -> Dict[str, bool]:
    """Single source of truth for the 5-rule checklist."""
    return {
        "length": len(password) >= 8,
        "uppercase": bool(UPPER_REGEX.search(password)),
        "lowercase": bool(LOWER_REGEX.search(password)),
        "number": bool(DIGIT_REGEX.search(password)),
        "special": bool(SPECIAL_REGEX.search(password)),
    }


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy bits based on character pool cardinality."""
    if not password:
        return 0.0

    pool = 0
    if LOWER_REGEX.search(password):
        pool += 26
    if UPPER_REGEX.search(password):
        pool += 26
    if DIGIT_REGEX.search(password):
        pool += 10
    if SPECIAL_REGEX.search(password):
        pool += 33

    if pool == 0:
        return 0.0

    return round(len(password) * math.log2(pool), 1)


def estimate_crack_time(entropy_bits: float) -> str:
    """
    Estimate crack time against modern offline GPU cluster (10^10 hashes/sec).
    """
    if entropy_bits <= 0:
        return "Instant"

    combinations = 2 ** entropy_bits
    seconds = combinations / 1e10

    if seconds < 1:
        return "Instant"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds / 86400)} days"
    elif seconds < 3153600000:
        return f"{int(seconds / 31536000)} years"
    else:
        return "Centuries"


def normalize_leetspeak(text: str) -> str:
    """Translate leetspeak characters to plain Latin alphabet for pattern matching."""
    res = []
    for ch in text.lower():
        res.append(LEET_REPLACEMENTS.get(ch, ch))
    return "".join(res)


def detect_penalties(
    password: str,
    user_name: Optional[str] = None,
    user_email: Optional[str] = None
) -> Dict[str, Any]:
    """Detect common weakness patterns, repetitions, and personal data."""
    penalties: List[str] = []
    suggestions: List[str] = []
    penalty_score = 0

    lower = password.lower()
    de_leeted = normalize_leetspeak(password)

    # 1. Repeated consecutive characters (e.g. 'aaa', '1111')
    if re.search(r"(.)\1{2,}", password):
        penalties.append("Consecutive repeated characters detected")
        suggestions.append("Avoid repeating the same character 3 or more times.")
        penalty_score += 12

    # 2. Sequential numbers or letters (e.g. 'abc', '123', '789')
    has_seq = False
    for i in range(len(password) - 2):
        chunk = password[i:i+3].lower()
        if (ord(chunk[1]) == ord(chunk[0]) + 1 and ord(chunk[2]) == ord(chunk[1]) + 1) or \
           (ord(chunk[1]) == ord(chunk[0]) - 1 and ord(chunk[2]) == ord(chunk[1]) - 1):
            has_seq = True
            break
    if has_seq:
        penalties.append("Sequential characters (e.g., '123' or 'abc')")
        suggestions.append("Avoid obvious alphabetical or numeric sequences.")
        penalty_score += 15

    # 3. Keyboard walks (e.g., 'qwerty', 'asdf')
    for pat in KEYBOARD_PATTERNS:
        if pat in lower or pat in de_leeted:
            penalties.append(f"Keyboard pattern detected ('{pat[:4]}...')")
            suggestions.append("Avoid keyboard sequences like 'qwerty' or 'asdf'.")
            penalty_score += 20
            break

    # 4. Leetspeak variations of 'password'
    if "password" in de_leeted and "password" not in lower:
        penalties.append("Leetspeak variation of 'password'")
        suggestions.append("Leetspeak substitutes (e.g., P@ssw0rd) are easily cracked by automated tools.")
        penalty_score += 15

    # 5. User Personal Information Inclusion
    if user_name and len(user_name.strip()) >= 3:
        for part in user_name.lower().split():
            if len(part) >= 3 and (part in lower or part in de_leeted):
                penalties.append("Contains your name or parts of your full name")
                suggestions.append("Never include your name in your password.")
                penalty_score += 25
                break

    if user_email and "@" in user_email:
        handle = user_email.split("@")[0].lower()
        if len(handle) >= 3 and (handle in lower or handle in de_leeted):
            penalties.append("Contains your email username")
            suggestions.append("Do not use parts of your email address inside passwords.")
            penalty_score += 25

    return {
        "penalties": penalties,
        "suggestions": suggestions,
        "penalty_score": penalty_score
    }


def analyze_password_strength(
    password: str,
    user_name: Optional[str] = None,
    user_email: Optional[str] = None,
    is_reused: bool = False
) -> Dict[str, Any]:
    """
    Evaluates password strength on a 0-100 scale.
    Categorizes into 'weak' (0-39), 'medium' (40-69), and 'strong' (70-100).
    """
    if not password:
        return {
            "score": 0,
            "level": "weak",
            "title": "Waiting for password...",
            "message": "Type a password and click Check.",
            "checks": get_criteria_state(""),
            "entropy_bits": 0.0,
            "crack_time": "Instant",
            "is_common": False,
            "is_reused": False,
            "is_available": True,
            "suggestions": ["Enter a password to inspect its security profile."],
            "penalties": []
        }

    checks = get_criteria_state(password)
    length = len(password)
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    is_common = is_common_password(password)

    # Base score construction
    raw_score = 0

    # 1. Length scoring (up to 40 pts)
    if length < 8:
        raw_score += max(0, length * 2)
    elif length < 12:
        raw_score += 15 + (length - 8) * 3  # 15 to 24 pts
    elif length < 16:
        raw_score += 28 + (length - 12) * 2  # 28 to 34 pts
    else:
        raw_score += min(40, 36 + (length - 16))  # 36 to 40 pts

    # 2. Character diversity scoring (up to 30 pts)
    variety_count = sum(1 for v in [checks["uppercase"], checks["lowercase"], checks["number"], checks["special"]] if v)
    if checks["lowercase"]:
        raw_score += 5
    if checks["uppercase"]:
        raw_score += 7
    if checks["number"]:
        raw_score += 8
    if checks["special"]:
        raw_score += 10

    # Bonus for all 4 types present
    if variety_count == 4 and length >= 10:
        raw_score += 5

    # 3. Entropy factor (up to 25 pts)
    if entropy >= 80:
        raw_score += 25
    elif entropy >= 60:
        raw_score += 18
    elif entropy >= 45:
        raw_score += 12
    elif entropy >= 30:
        raw_score += 6

    # Pattern and penalty deductions
    penalty_analysis = detect_penalties(password, user_name, user_email)
    raw_score -= penalty_analysis["penalty_score"]

    if is_reused:
        raw_score -= 10
        penalty_analysis["penalties"].append("Password previously checked by your account")
        penalty_analysis["suggestions"].append("This password was previously evaluated by you. Avoid reusing passwords across accounts.")

    # Top common password hard-cap
    if is_common:
        raw_score = min(raw_score, 10)
        penalty_analysis["penalties"].append("Commonly used or breached dictionary password")
        penalty_analysis["suggestions"].append("This password appears in breach dictionaries. Never use common passwords.")

    # Clamp score to [0, 100]
    final_score = max(0, min(100, int(round(raw_score))))

    # Suggestion enhancements based on missing rules
    suggestions = list(penalty_analysis["suggestions"])
    if not checks["length"]:
        suggestions.insert(0, "Increase length to at least 12 characters (16+ recommended).")
    if not checks["special"]:
        suggestions.append("Add special symbols like !, @, #, $, or %.")
    if not checks["number"]:
        suggestions.append("Include digits to raise entropy.")
    if not checks["uppercase"]:
        suggestions.append("Include uppercase letters.")
    if not checks["lowercase"]:
        suggestions.append("Include lowercase letters.")

    # Level classification
    if final_score < 40 or is_common:
        level = "weak"
        title = "Weak"
        if is_common:
            message = "This password is widely known and compromised. It offers zero protection."
        else:
            message = "This password is vulnerable to dictionary and brute-force attacks."
    elif final_score < 70:
        level = "medium"
        title = "Medium"
        message = "Reasonable password strength, but could be made significantly more resilient."
    else:
        level = "strong"
        title = "Strong"
        message = "Excellent! Highly resistant to offline cracking and dictionary attacks."

    # Availability calculation
    # Common = found in wordlist; Reused = checked before by user; Available = neither common nor reused
    is_available = (not is_common) and (not is_reused)

    return {
        "score": final_score,
        "level": level,
        "title": title,
        "message": message,
        "checks": checks,
        "entropy_bits": entropy,
        "crack_time": crack_time,
        "is_common": is_common,
        "is_reused": is_reused,
        "is_available": is_available,
        "suggestions": suggestions[:4],  # Top relevant suggestions
        "penalties": penalty_analysis["penalties"]
    }
