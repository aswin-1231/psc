/**
 * PassGuard Password Checker Page Controller
 * Features 300ms input debouncing, live entropy & crack-time preview,
 * single-popup on Check submission, 3 status badge separation, and HIBP verification.
 */

document.addEventListener("DOMContentLoaded", () => {
  const pwdInput = document.getElementById("checkerPasswordInput");
  const toggleBtn = document.getElementById("checkerToggleVisibility");
  const btnCheck = document.getElementById("btnCheckSubmit");
  const btnHibp = document.getElementById("btnHibpCheck");

  const fillBar = document.getElementById("meterFillBar");
  const scoreLabel = document.getElementById("meterScoreLabel");
  const levelBadge = document.getElementById("meterLevelBadge");
  const bannerTitle = document.getElementById("resultBannerTitle");
  const bannerMessage = document.getElementById("resultBannerMessage");
  const bannerEl = document.getElementById("resultBanner");

  const metricCrack = document.getElementById("metricCrackTime");
  const metricEntropy = document.getElementById("metricEntropy");
  const suggestionsList = document.getElementById("suggestionsList");

  const badgeCommonEl = document.getElementById("badgeCommon");
  const badgeCommonState = document.getElementById("badgeCommonState");
  const badgeReusedEl = document.getElementById("badgeReused");
  const badgeReusedState = document.getElementById("badgeReusedState");
  const badgeAvailableEl = document.getElementById("badgeAvailable");
  const badgeAvailableState = document.getElementById("badgeAvailableState");
  const hibpAlert = document.getElementById("hibpStatusAlert");

  const ruleEls = {
    length: document.getElementById("checkLength"),
    uppercase: document.getElementById("checkUppercase"),
    lowercase: document.getElementById("checkLowercase"),
    number: document.getElementById("checkNumber"),
    special: document.getElementById("checkSpecial")
  };

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

  let currentAnalysis = null;
  let lastSavedCheckId = null;

  // Show / Hide password visibility
  if (toggleBtn && pwdInput) {
    toggleBtn.addEventListener("click", () => {
      const isHidden = pwdInput.type === "password";
      pwdInput.type = isHidden ? "text" : "password";
      toggleBtn.textContent = isHidden ? "🙈" : "👁";
      toggleBtn.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
    });
  }

  // Toast helper for isolated single popups
  function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span class="toast-message">${message}</span>
      <button type="button" class="btn-sm" style="background:transparent;border:none;color:inherit;cursor:pointer;">&times;</button>
    `;
    toast.querySelector("button").onclick = () => toast.remove();
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.transition = "opacity 0.4s ease, transform 0.4s ease";
      toast.style.opacity = "0";
      toast.style.transform = "translateX(40px)";
      setTimeout(() => toast.remove(), 400);
    }, 4000);
  }

  /**
   * Update visual checklist with pop animation
   */
  function updateChecklist(checks) {
    for (const [key, el] of Object.entries(ruleEls)) {
      if (el) {
        const passed = Boolean(checks[key]);
        const wasPassed = el.classList.contains("pass");
        el.classList.toggle("pass", passed);
        el.classList.toggle("fail", !passed);

        const icon = el.querySelector(".rule-icon");
        if (icon) {
          icon.textContent = passed ? "✓" : "✕";
          if (passed && !wasPassed) {
            icon.style.animation = "none";
            // trigger reflow
            void icon.offsetWidth;
            icon.style.animation = "pop 0.25s ease-out";
          }
        }
      }
    }
  }

  /**
   * Update status badges for Common, Reused, and Available
   */
  function updateStatusBadges(isCommon, isReused, isAvailable) {
    // 1. Common Badge
    if (isCommon) {
      badgeCommonEl.className = "status-badge-item active-danger";
      badgeCommonState.textContent = "Yes";
    } else {
      badgeCommonEl.className = "status-badge-item";
      badgeCommonState.textContent = "No";
    }

    // 2. Reused Badge
    if (isReused) {
      badgeReusedEl.className = "status-badge-item active-warning";
      badgeReusedState.textContent = "Yes";
    } else {
      badgeReusedEl.className = "status-badge-item";
      badgeReusedState.textContent = "No";
    }

    // 3. Available Badge
    if (isAvailable) {
      badgeAvailableEl.className = "status-badge-item active-success";
      badgeAvailableState.textContent = "Yes";
    } else {
      badgeAvailableEl.className = "status-badge-item";
      badgeAvailableState.textContent = "No";
    }
  }

  /**
   * Apply evaluation result to DOM
   */
  function applyAnalysisResult(res) {
    currentAnalysis = res;
    const score = res.score || 0;
    const level = res.level || "weak";

    // Progress bar fill & color transition
    fillBar.style.width = `${score}%`;
    fillBar.className = `meter-fill ${level}`;
    scoreLabel.textContent = `Score: ${score} / 100`;

    levelBadge.textContent = level.toUpperCase();
    levelBadge.className = `badge badge-${level}`;

    // Banner
    bannerTitle.textContent = res.title || "Evaluation Complete";
    bannerMessage.textContent = res.message || "";
    bannerEl.style.borderLeftColor = level === "strong" ? "var(--color-strong)" : (level === "medium" ? "var(--color-medium)" : "var(--color-weak)");

    // Metrics
    metricCrack.textContent = res.crack_time || "Instant";
    metricEntropy.textContent = `${res.entropy_bits || 0} bits`;

    // Checklist
    updateChecklist(res.checks || {});

    // Badges
    updateStatusBadges(res.is_common, res.is_reused, res.is_available);

    // Suggestions
    suggestionsList.innerHTML = "";
    const suggestions = res.suggestions || [];
    if (suggestions.length === 0) {
      suggestionsList.innerHTML = "<li>Password complies with optimal security guidelines.</li>";
    } else {
      suggestions.forEach((s) => {
        const li = document.createElement("li");
        li.textContent = s;
        suggestionsList.appendChild(li);
      });
    }
  }

  /**
   * 300ms Debounced live evaluation handler
   */
  async function performLiveAnalysis() {
    const password = pwdInput.value;
    if (!password.trim()) {
      applyAnalysisResult(window.PassGuardStrength.evaluateLiveScore(""));
      updateStatusBadges(false, false, true);
      hibpAlert.style.display = "none";
      return;
    }

    // Instant local preview
    const local = window.PassGuardStrength.evaluateLiveScore(password);
    applyAnalysisResult({
      ...local,
      entropy_bits: local.entropy,
      crack_time: local.crackTime,
      is_common: false,
      is_reused: false,
      is_available: true,
      suggestions: ["Analyzing against secure server engine..."]
    });

    // Query backend single source of truth engine
    try {
      const response = await fetch("/api/checker/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify({ password })
      });
      if (response.ok) {
        const serverResult = await response.json();
        applyAnalysisResult(serverResult);
      }
    } catch (err) {
      console.warn("Live server analysis failed, using client preview:", err);
    }
  }

  const debouncedInputHandler = window.PassGuardStrength.debounce(performLiveAnalysis, 300);
  pwdInput.addEventListener("input", debouncedInputHandler);

  /**
   * Check & Save button click handler
   */
  btnCheck.addEventListener("click", async () => {
    const password = pwdInput.value;
    if (!password.trim()) {
      pwdInput.classList.add("invalid");
      showToast("Please enter a password to evaluate.", "warning");
      setTimeout(() => pwdInput.classList.remove("invalid"), 600);
      return;
    }

    btnCheck.disabled = true;
    btnCheck.innerHTML = "<span>Saving check...</span>";

    try {
      const response = await fetch("/api/checker/save", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify({ password })
      });

      const data = await response.json();
      btnCheck.disabled = false;
      btnCheck.innerHTML = "<span>🛡️ Check & Save to History</span>";

      if (response.ok) {
        lastSavedCheckId = data.check_id;
        applyAnalysisResult(data.result);

        // Show common password toast only when Check button is clicked!
        if (data.result.is_common) {
          showToast("⚠️ This password appears in common breach dictionaries. Choose a unique password!", "danger");
        } else if (data.result.is_reused) {
          showToast("🔄 Notice: This password was previously evaluated by your account.", "warning");
        } else {
          showToast("✅ Password evaluation recorded securely in your history.", "success");
        }
      } else {
        showToast(data.message || "Could not save password check.", "danger");
      }
    } catch (err) {
      btnCheck.disabled = false;
      btnCheck.innerHTML = "<span>🛡️ Check & Save to History</span>";
      showToast("Network error while recording check.", "danger");
    }
  });

  /**
   * Have I Been Pwned k-anonymity check handler
   */
  btnHibp.addEventListener("click", async () => {
    const password = pwdInput.value;
    if (!password.trim()) {
      showToast("Enter a password first to query Have I Been Pwned.", "warning");
      return;
    }

    btnHibp.disabled = true;
    btnHibp.innerHTML = "<span>Querying HIBP...</span>";
    hibpAlert.style.display = "block";
    hibpAlert.style.background = "rgba(56, 189, 248, 0.1)";
    hibpAlert.style.border = "1px solid var(--cyan)";
    hibpAlert.style.color = "var(--cyan)";
    hibpAlert.textContent = "Connecting to HIBP k-anonymity API (only first 5 chars of SHA-1 hash sent)...";

    try {
      const response = await fetch("/api/checker/hibp", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify({ password, check_id: lastSavedCheckId })
      });

      const data = await response.json();
      btnHibp.disabled = false;
      btnHibp.innerHTML = "<span>🌐 Check if Breached (HIBP)</span>";

      if (response.ok && data.is_breached) {
        hibpAlert.style.background = "rgba(239, 68, 68, 0.15)";
        hibpAlert.style.border = "1px solid var(--color-weak)";
        hibpAlert.style.color = "var(--color-weak)";
        hibpAlert.innerHTML = `🚨 <strong>Breach Warning:</strong> This password has appeared <strong>${data.breach_count.toLocaleString()}</strong> times in data breaches tracked by Have I Been Pwned.`;
        showToast(`Exposed in ${data.breach_count.toLocaleString()} breaches!`, "danger");
      } else {
        hibpAlert.style.background = "rgba(34, 197, 94, 0.15)";
        hibpAlert.style.border = "1px solid var(--color-strong)";
        hibpAlert.style.color = "var(--color-strong)";
        hibpAlert.innerHTML = "🛡️ <strong>Zero Breaches Found:</strong> No exposure matches detected in Have I Been Pwned.";
        showToast("No breach matches found in HIBP.", "success");
      }
    } catch (err) {
      btnHibp.disabled = false;
      btnHibp.innerHTML = "<span>🌐 Check if Breached (HIBP)</span>";
      hibpAlert.textContent = "HIBP check temporarily unreachable (network or offline).";
    }
  });

  // Initial trigger with blank state
  applyAnalysisResult(window.PassGuardStrength.evaluateLiveScore(""));
});
