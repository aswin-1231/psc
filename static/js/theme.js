/**
 * PassGuard Theme Controller
 * Synchronizes dark and light theme state with localStorage persistence.
 */
(() => {
  const THEME_KEY = "passguard_theme";
  const body = document.body;
  const toggleBtns = document.querySelectorAll("#themeToggleBtn, .theme-btn");

  function getSavedTheme() {
    return localStorage.getItem(THEME_KEY) || "dark";
  }

  function applyTheme(theme) {
    const isLight = theme === "light";
    body.classList.toggle("light", isLight);
    localStorage.setItem(THEME_KEY, theme);

    toggleBtns.forEach((btn) => {
      btn.innerHTML = isLight ? "☀️ Light" : "🌙 Dark";
      btn.setAttribute(
        "aria-label",
        isLight ? "Switch to dark mode" : "Switch to light mode"
      );
    });
  }

  // Bind click handlers to all theme buttons
  toggleBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const current = body.classList.contains("light") ? "light" : "dark";
      applyTheme(current === "light" ? "dark" : "light");
    });
  });

  // Initialize on page load
  applyTheme(getSavedTheme());
})();
