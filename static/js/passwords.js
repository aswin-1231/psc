/**
 * PassGuard Passwords Page Controller
 * Manages Available suggestions generator (length slider, options, copy animations)
 * and Already Used zero-knowledge history (masked items, deletion, clear confirmation).
 */

document.addEventListener("DOMContentLoaded", () => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

  // View switch tabs
  const tabBtnAvailable = document.getElementById("tabBtnAvailable");
  const tabBtnUsed = document.getElementById("tabBtnUsed");
  const panelAvailable = document.getElementById("panelAvailable");
  const panelUsed = document.getElementById("panelUsed");

  // Generator controls
  const lengthSlider = document.getElementById("lengthSlider");
  const lengthDisplay = document.getElementById("lengthValueDisplay");
  const chkUpper = document.getElementById("chkUpper");
  const chkLower = document.getElementById("chkLower");
  const chkDigits = document.getElementById("chkDigits");
  const chkSpecial = document.getElementById("chkSpecial");
  const btnRegenAll = document.getElementById("btnRegenerateAll");
  const suggestionsContainer = document.getElementById("suggestionsListContainer");

  // History controls
  const historyContainer = document.getElementById("historyListContainer");
  const btnClearHistory = document.getElementById("btnClearHistory");

  /**
   * Switch active tabs on mobile / tablet
   */
  if (tabBtnAvailable && tabBtnUsed) {
    tabBtnAvailable.addEventListener("click", () => {
      tabBtnAvailable.classList.add("active");
      tabBtnUsed.classList.remove("active");
      panelAvailable.style.display = "block";
      if (window.innerWidth <= 1024) panelUsed.style.display = "none";
    });

    tabBtnUsed.addEventListener("click", () => {
      tabBtnUsed.classList.add("active");
      tabBtnAvailable.classList.remove("active");
      panelUsed.style.display = "block";
      if (window.innerWidth <= 1024) panelAvailable.style.display = "none";
    });

    // Reset visibility on window resize
    window.addEventListener("resize", () => {
      if (window.innerWidth > 1024) {
        panelAvailable.style.display = "block";
        panelUsed.style.display = "block";
      } else {
        if (tabBtnAvailable.classList.contains("active")) {
          panelAvailable.style.display = "block";
          panelUsed.style.display = "none";
        } else {
          panelAvailable.style.display = "none";
          panelUsed.style.display = "block";
        }
      }
    });
  }

  /**
   * Copy to clipboard with pulse animation & "Copied!" text feedback
   */
  async function copyToClipboard(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      const originalText = btn.innerHTML;
      btn.innerHTML = "<span>✓ Copied!</span>";
      btn.classList.add("copied");

      setTimeout(() => {
        btn.innerHTML = originalText;
        btn.classList.remove("copied");
      }, 1800);
    } catch (err) {
      console.error("Clipboard copy failed:", err);
    }
  }

  /**
   * Fetch 10 freshly generated strong suggestions
   */
  async function fetchGeneratedPasswords() {
    suggestionsContainer.innerHTML = `
      <div style="text-align: center; padding: 24px; color: var(--text-dim);">
        Generating cryptographically secure suggestions...
      </div>
    `;

    try {
      const response = await fetch("/api/passwords/generate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify({
          length: parseInt(lengthSlider.value, 10),
          include_upper: chkUpper.checked,
          include_lower: chkLower.checked,
          include_digits: chkDigits.checked,
          include_special: chkSpecial.checked
        })
      });

      if (!response.ok) return;

      const data = await response.json();
      const list = data.suggestions || [];
      renderSuggestions(list);
    } catch (err) {
      suggestionsContainer.innerHTML = `
        <div style="text-align: center; padding: 24px; color: var(--color-weak);">
          Failed to generate passwords. Please try again.
        </div>
      `;
    }
  }

  function renderSuggestions(list) {
    suggestionsContainer.innerHTML = "";
    if (list.length === 0) {
      suggestionsContainer.innerHTML = `<div style="text-align: center; padding: 24px; color: var(--text-muted);">No suggestions available.</div>`;
      return;
    }

    list.forEach((item) => {
      const card = document.createElement("div");
      card.className = "suggestion-card";

      const left = document.createElement("div");
      left.style.overflow = "hidden";
      left.style.marginRight = "10px";

      const pwdEl = document.createElement("div");
      pwdEl.className = "suggestion-pwd";
      pwdEl.textContent = item.password;

      const metaEl = document.createElement("div");
      metaEl.style.fontSize = "0.78rem";
      metaEl.style.color = "var(--text-dim)";
      metaEl.style.marginTop = "2px";
      metaEl.textContent = `${item.type} • ${item.length} chars • Entropy: ${item.entropy_bits} bits • Crack time: ${item.crack_time}`;

      left.appendChild(pwdEl);
      left.appendChild(metaEl);

      const actions = document.createElement("div");
      actions.className = "suggestion-actions";

      const badge = document.createElement("span");
      badge.className = `badge badge-${item.level}`;
      badge.textContent = item.level.toUpperCase();

      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "copy-btn";
      copyBtn.innerHTML = "<span>📋 Copy</span>";
      copyBtn.onclick = () => copyToClipboard(item.password, copyBtn);

      actions.appendChild(badge);
      actions.appendChild(copyBtn);

      card.appendChild(left);
      card.appendChild(actions);
      suggestionsContainer.appendChild(card);
    });
  }

  /**
   * Fetch Already Used masked history
   */
  async function fetchHistory() {
    historyContainer.innerHTML = `
      <div style="text-align: center; padding: 24px; color: var(--text-dim);">
        Loading history...
      </div>
    `;

    try {
      const response = await fetch("/api/passwords/history", {
        headers: { "X-Requested-With": "XMLHttpRequest" }
      });
      if (!response.ok) return;

      const data = await response.json();
      renderHistory(data.history || []);
    } catch (err) {
      historyContainer.innerHTML = `
        <div style="text-align: center; padding: 24px; color: var(--color-weak);">
          Failed to load history.
        </div>
      `;
    }
  }

  function renderHistory(items) {
    historyContainer.innerHTML = "";
    if (items.length === 0) {
      historyContainer.innerHTML = `
        <div style="text-align: center; padding: 32px; color: var(--text-dim);">
          No evaluated passwords in your history yet.<br>
          <a href="/checker" style="color: var(--cyan); margin-top: 8px; display: inline-block;">Go to Password Checker</a>
        </div>
      `;
      return;
    }

    items.forEach((item) => {
      const card = document.createElement("div");
      card.className = "suggestion-card";

      const left = document.createElement("div");
      left.style.overflow = "hidden";
      left.style.marginRight = "10px";

      const maskEl = document.createElement("div");
      maskEl.className = "suggestion-pwd";
      maskEl.style.color = "var(--cyan)";
      maskEl.textContent = item.masked_preview;

      const metaEl = document.createElement("div");
      metaEl.style.fontSize = "0.78rem";
      metaEl.style.color = "var(--text-dim)";
      metaEl.style.marginTop = "2px";
      metaEl.textContent = `${item.length} chars • Evaluated ${item.times_checked} time(s) • Last checked: ${item.checked_at}`;

      left.appendChild(maskEl);
      left.appendChild(metaEl);

      const actions = document.createElement("div");
      actions.className = "suggestion-actions";

      const badge = document.createElement("span");
      badge.className = `badge badge-${item.level}`;
      badge.textContent = `${item.score}/100`;

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "btn-sm btn-danger";
      deleteBtn.innerHTML = "<span>🗑️</span>";
      deleteBtn.title = "Delete this evaluation record";
      deleteBtn.onclick = () => deleteHistoryItem(item.id, card);

      actions.appendChild(badge);
      actions.appendChild(deleteBtn);

      card.appendChild(left);
      card.appendChild(actions);
      historyContainer.appendChild(card);
    });
  }

  async function deleteHistoryItem(id, cardEl) {
    try {
      const res = await fetch(`/api/passwords/history/${id}`, {
        method: "DELETE",
        headers: {
          "X-CSRFToken": csrfToken,
          "X-Requested-With": "XMLHttpRequest"
        }
      });
      if (res.ok) {
        cardEl.style.transition = "all 0.3s ease";
        cardEl.style.opacity = "0";
        cardEl.style.transform = "translateX(20px)";
        setTimeout(() => {
          cardEl.remove();
          if (historyContainer.children.length === 0) {
            fetchHistory();
          }
        }, 300);
      }
    } catch (err) {
      console.error("Failed to delete history item:", err);
    }
  }

  // Clear all history with confirmation dialog
  if (btnClearHistory) {
    btnClearHistory.addEventListener("click", async () => {
      if (!confirm("Are you sure you want to permanently clear all password evaluation history? This cannot be undone.")) {
        return;
      }

      try {
        const res = await fetch("/api/passwords/history/clear", {
          method: "DELETE",
          headers: {
            "X-CSRFToken": csrfToken,
            "X-Requested-With": "XMLHttpRequest"
          }
        });
        if (res.ok) {
          fetchHistory();
        }
      } catch (err) {
        console.error("Failed to clear history:", err);
      }
    });
  }

  // Length slider listener
  if (lengthSlider && lengthDisplay) {
    lengthSlider.addEventListener("input", () => {
      lengthDisplay.textContent = `${lengthSlider.value} characters`;
    });
    lengthSlider.addEventListener("change", fetchGeneratedPasswords);
  }

  [chkUpper, chkLower, chkDigits, chkSpecial].forEach((chk) => {
    if (chk) chk.addEventListener("change", fetchGeneratedPasswords);
  });

  if (btnRegenAll) {
    btnRegenAll.addEventListener("click", fetchGeneratedPasswords);
  }

  // Initial loads
  fetchGeneratedPasswords();
  fetchHistory();
});
