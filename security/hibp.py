"""
Have I Been Pwned (HIBP) k-Anonymity API Client.
Verifies password breach exposure while strictly protecting confidentiality.
Only the first 5 hex characters of the SHA-1 hash are transmitted.
"""

import hashlib
import logging
import requests
from typing import Tuple

logger = logging.getLogger(__name__)

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def check_hibp_breach(password: str, timeout: int = 4) -> Tuple[bool, int]:
    """
    Check if a password has been compromised in known breaches.
    
    Returns:
        (is_breached: bool, count: int)
    """
    if not password:
        return False, 0

    try:
        # Calculate full SHA-1 hash in uppercase
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Query HIBP k-anonymity endpoint
        headers = {
            "User-Agent": "PassGuard-Security-Suite/1.0",
            "Add-Padding": "true"  # Mitigate side-channel response length attacks
        }
        response = requests.get(f"{HIBP_API_URL}{prefix}", headers=headers, timeout=timeout)

        if response.status_code != 200:
            logger.warning(f"HIBP API returned status {response.status_code}")
            return False, 0

        # Parse suffixes and counts
        hashes = (line.split(":") for line in response.text.splitlines() if ":" in line)
        for h_suffix, count_str in hashes:
            if h_suffix.strip().upper() == suffix:
                try:
                    count = int(count_str.strip())
                    return True, count
                except ValueError:
                    return True, 1

        return False, 0

    except requests.RequestException as e:
        logger.warning(f"Could not connect to HIBP API (offline or timeout): {e}")
        return False, 0
    except Exception as e:
        logger.error(f"Unexpected error in HIBP breach check: {e}")
        return False, 0
