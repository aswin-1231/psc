/**
 * PassGuard Single Source of Truth Client Strength Engine
 * Consolidates regular expressions, 5-rule criteria, client entropy estimation,
 * and debouncing utility.
 */

window.PassGuardStrength = (() => {
  // Single Source of Truth Regular Expressions
  const REGEX = {
    upper: /[A-Z]/,
    lower: /[a-z]/,
    digit: /\d/,
    special: /[!@#$%^&*(),.?":{}|<>_\-+=/\\[\]~`]/
  };

  /**
   * Debounce utility to prevent input lag and request hammering.
   */
  function debounce(func, wait = 300) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  /**
   * Single Source of Truth for the 5-rule checklist.
   */
  function getCriteriaState(password) {
    if (!password) {
      return {
        length: false,
        uppercase: false,
        lowercase: false,
        number: false,
        special: false
      };
    }
    return {
      length: password.length >= 8,
      uppercase: REGEX.upper.test(password),
      lowercase: REGEX.lower.test(password),
      number: REGEX.digit.test(password),
      special: REGEX.special.test(password)
    };
  }

  /**
   * Client-side Shannon entropy estimation.
   */
  function calculateEntropy(password) {
    if (!password) return 0;
    let pool = 0;
    if (REGEX.lower.test(password)) pool += 26;
    if (REGEX.upper.test(password)) pool += 26;
    if (REGEX.digit.test(password)) pool += 10;
    if (REGEX.special.test(password)) pool += 33;
    if (pool === 0) return 0;
    return Math.round(password.length * Math.log2(pool) * 10) / 10;
  }

  /**
   * Crack time estimate against 10^10 hashes/sec offline GPU rig.
   */
  function estimateCrackTime(entropy) {
    if (entropy <= 0) return "Instant";
    const seconds = Math.pow(2, entropy) / 1e10;
    if (seconds < 1) return "Instant";
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} years`;
    return "Centuries";
  }

  /**
   * Client-side score preview generator (mirrors server logic).
   */
  function evaluateLiveScore(password) {
    if (!password || !password.trim()) {
      return {
        score: 0,
        level: "weak",
        title: "Waiting for password...",
        message: "Type a password and click Check.",
        checks: getCriteriaState(""),
        entropy: 0,
        crackTime: "Instant"
      };
    }

    const checks = getCriteriaState(password);
    const length = password.length;
    const entropy = calculateEntropy(password);
    const crackTime = estimateCrackTime(entropy);

    let rawScore = 0;

    // Length score (up to 40)
    if (length < 8) {
      rawScore += Math.max(0, length * 2);
    } else if (length < 12) {
      rawScore += 15 + (length - 8) * 3;
    } else if (length < 16) {
      rawScore += 28 + (length - 12) * 2;
    } else {
      rawScore += Math.min(40, 36 + (length - 16));
    }

    // Variety score (up to 30)
    if (checks.lowercase) rawScore += 5;
    if (checks.uppercase) rawScore += 7;
    if (checks.number) rawScore += 8;
    if (checks.special) rawScore += 10;

    // Bonus for variety
    const varietyCount = [checks.lowercase, checks.uppercase, checks.number, checks.special].filter(Boolean).length;
    if (varietyCount === 4 && length >= 10) rawScore += 5;

    // Entropy contribution (up to 25)
    if (entropy >= 80) rawScore += 25;
    else if (entropy >= 60) rawScore += 18;
    else if (entropy >= 45) rawScore += 12;
    else if (entropy >= 30) rawScore += 6;

    // Basic pattern deductions
    if (/(.)\1{2,}/.test(password)) rawScore -= 12; // repeats

    // Clamp
    const score = Math.max(0, Math.min(100, Math.round(rawScore)));

    let level = "weak";
    let title = "Weak";
    let message = "Vulnerable to automated brute-force.";

    if (score >= 70) {
      level = "strong";
      title = "Strong";
      message = "Excellent! High cryptographic entropy.";
    } else if (score >= 40) {
      level = "medium";
      title = "Medium";
      message = "Acceptable, but can be hardened with length or symbols.";
    }

    return {
      score,
      level,
      title,
      message,
      checks,
      entropy,
      crackTime
    };
  }

  return {
    getCriteriaState,
    calculateEntropy,
    estimateCrackTime,
    evaluateLiveScore,
    debounce
  };
})();
