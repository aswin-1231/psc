/**
 * PassGuard Dashboard Analytics Controller
 * Handles animated number count-ups, Chart.js timeline and doughnut distribution rendering,
 * and 7d / 30d range toggles.
 */

document.addEventListener("DOMContentLoaded", () => {
  let timelineChartInstance = null;
  let distributionChartInstance = null;

  // CSRF helper
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

  /**
   * Smooth 60fps number count-up animation
   */
  function animateValue(element, start, end, duration = 1000) {
    if (!element) return;
    if (start === end) {
      element.textContent = end;
      return;
    }
    const range = end - start;
    let current = start;
    const increment = end > start ? 1 : -1;
    const stepTime = Math.abs(Math.floor(duration / (range || 1)));
    const startTime = performance.now();

    function step(timestamp) {
      const progress = Math.min((timestamp - startTime) / duration, 1);
      // Ease-out cubic
      const easedProgress = 1 - Math.pow(1 - progress, 3);
      element.textContent = Math.floor(start + range * easedProgress);

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        element.textContent = end;
      }
    }
    requestAnimationFrame(step);
  }

  /**
   * Fetch and animate dashboard metric cards
   */
  async function loadDashboardStats() {
    try {
      const response = await fetch("/api/dashboard/stats", {
        headers: { "X-Requested-With": "XMLHttpRequest" }
      });
      if (!response.ok) return;

      const data = await response.json();
      const user = data.user_stats || {};
      const global = data.global_stats || {};

      // Animate Personal Stats
      animateValue(document.getElementById("statTotal"), 0, user.total_checked || 0);
      animateValue(document.getElementById("statStrong"), 0, user.strong || 0);
      animateValue(document.getElementById("statMedium"), 0, user.medium || 0);
      animateValue(document.getElementById("statWeak"), 0, user.weak || 0);
      animateValue(document.getElementById("statCommon"), 0, user.common_or_breached || 0);
      animateValue(document.getElementById("statReused"), 0, user.reused || 0);

      // Populate Global Totals
      document.getElementById("statGlobalTotal").textContent = global.total_checked || 0;
      document.getElementById("statGlobalStrong").textContent = global.strong || 0;
      document.getElementById("statGlobalMedium").textContent = global.medium || 0;
      document.getElementById("statGlobalWeak").textContent = global.weak || 0;
      document.getElementById("statGlobalCommon").textContent = global.common_or_breached || 0;
      document.getElementById("statGlobalReused").textContent = global.reused || 0;
    } catch (err) {
      console.error("Failed to load dashboard stats:", err);
    }
  }

  /**
   * Render Chart.js Timeline and Distribution Charts
   */
  async function loadChartData(range = "7d") {
    try {
      const response = await fetch(`/api/dashboard/chart?range=${range}`, {
        headers: { "X-Requested-With": "XMLHttpRequest" }
      });
      if (!response.ok) return;

      const data = await response.json();
      const timeline = data.timeline || { labels: [], counts: [] };
      const dist = data.distribution || { strong: 0, medium: 0, weak: 0 };

      renderTimelineChart(timeline.labels, timeline.counts);
      renderDistributionChart(dist.strong, dist.medium, dist.weak);
    } catch (err) {
      console.error("Failed to load chart data:", err);
    }
  }

  function renderTimelineChart(labels, counts) {
    const ctx = document.getElementById("timelineChart")?.getContext("2d");
    if (!ctx) return;

    if (timelineChartInstance) {
      timelineChartInstance.destroy();
    }

    const isLight = document.body.classList.contains("light");
    const gridColor = isLight ? "rgba(15, 23, 42, 0.08)" : "rgba(255, 255, 255, 0.08)";
    const textColor = isLight ? "#64748b" : "#94a3b8";

    // Gradient fill under the line
    const gradient = ctx.createLinearGradient(0, 0, 0, 260);
    gradient.addColorStop(0, "rgba(56, 189, 248, 0.35)");
    gradient.addColorStop(1, "rgba(56, 189, 248, 0.0)");

    timelineChartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [{
          label: "Passwords Evaluated",
          data: counts,
          borderColor: "#38bdf8",
          backgroundColor: gradient,
          borderWidth: 3,
          fill: true,
          tension: 0.35,
          pointBackgroundColor: "#8b5cf6",
          pointBorderColor: "#ffffff",
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(14, 25, 44, 0.95)",
            titleColor: "#38bdf8",
            bodyColor: "#f1f5f9",
            borderColor: "rgba(255, 255, 255, 0.12)",
            borderWidth: 1,
            padding: 10,
            displayColors: false
          }
        },
        scales: {
          x: {
            grid: { color: gridColor },
            ticks: { color: textColor }
          },
          y: {
            beginAtZero: true,
            ticks: { stepSize: 1, color: textColor },
            grid: { color: gridColor }
          }
        }
      }
    });
  }

  function renderDistributionChart(strong, medium, weak) {
    const ctx = document.getElementById("distributionChart")?.getContext("2d");
    if (!ctx) return;

    if (distributionChartInstance) {
      distributionChartInstance.destroy();
    }

    const total = strong + medium + weak;
    const hasData = total > 0;

    distributionChartInstance = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: hasData ? ["Strong", "Medium", "Weak"] : ["No Checks Yet"],
        datasets: [{
          data: hasData ? [strong, medium, weak] : [1],
          backgroundColor: hasData
            ? ["#22c55e", "#f59e0b", "#ef4444"]
            : ["rgba(148, 163, 184, 0.2)"],
          borderColor: "rgba(14, 25, 44, 0.8)",
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              boxWidth: 12,
              color: document.body.classList.contains("light") ? "#0f172a" : "#f1f5f9",
              padding: 14
            }
          },
          tooltip: {
            enabled: hasData,
            backgroundColor: "rgba(14, 25, 44, 0.95)",
            borderColor: "rgba(255, 255, 255, 0.12)",
            borderWidth: 1
          }
        },
        cutout: "68%"
      }
    });
  }

  // Range Toggle Event Listeners (7d / 30d)
  const btn7d = document.getElementById("btnRange7d");
  const btn30d = document.getElementById("btnRange30d");

  if (btn7d && btn30d) {
    btn7d.addEventListener("click", () => {
      btn7d.classList.add("active");
      btn30d.classList.remove("active");
      loadChartData("7d");
    });

    btn30d.addEventListener("click", () => {
      btn30d.classList.add("active");
      btn7d.classList.remove("active");
      loadChartData("30d");
    });
  }

  // Load initial dashboard metrics & charts
  loadDashboardStats();
  loadChartData("7d");
});
