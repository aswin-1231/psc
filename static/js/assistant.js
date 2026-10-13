/**
 * PassGuard AI Assistant Chat Controller
 * Features auto-scrolling, typing indicator, quick starter chips,
 * Enter-to-send keyboard handling, and history clearing.
 */

document.addEventListener("DOMContentLoaded", () => {
  const chatFeed = document.getElementById("chatFeed");
  const chatInput = document.getElementById("chatInput");
  const btnSend = document.getElementById("btnSendChat");
  const typingIndicator = document.getElementById("typingIndicator");
  const btnClearChat = document.getElementById("btnClearChat");
  const chipBtns = document.querySelectorAll(".chip-btn");

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content") || "";

  function scrollToBottom() {
    if (chatFeed) {
      chatFeed.scrollTop = chatFeed.scrollHeight;
    }
  }

  function escapeHTML(str) {
    const p = document.createElement("p");
    p.textContent = str;
    return p.innerHTML;
  }

  function appendMessage(role, text, timeStr) {
    const bubble = document.createElement("div");
    bubble.className = `chat-bubble ${role}`;

    // Format newlines safely
    const formatted = escapeHTML(text)
      .replace(/\n\n/g, "<br><br>")
      .replace(/\n/g, "<br>");

    bubble.innerHTML = `
      <div>${formatted}</div>
      <div class="chat-time">${timeStr || "Just now"}</div>
    `;

    // Insert before typing indicator
    if (typingIndicator) {
      chatFeed.insertBefore(bubble, typingIndicator);
    } else {
      chatFeed.appendChild(bubble);
    }

    scrollToBottom();
  }

  async function sendMessage(text) {
    const message = (text || chatInput.value || "").trim();
    if (!message) return;

    chatInput.value = "";
    chatInput.focus();

    const now = new Date();
    const timeStr = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;

    // Render User Bubble
    appendMessage("user", message, timeStr);

    // Show Typing Indicator
    if (typingIndicator) {
      typingIndicator.style.display = "flex";
      scrollToBottom();
    }
    if (btnSend) btnSend.disabled = true;

    try {
      const response = await fetch("/api/assistant/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-Requested-With": "XMLHttpRequest"
        },
        body: JSON.stringify({ message })
      });

      const data = await response.json();

      if (typingIndicator) typingIndicator.style.display = "none";
      if (btnSend) btnSend.disabled = false;

      if (response.ok) {
        appendMessage("assistant", data.reply, data.created_at || timeStr);
      } else {
        appendMessage("assistant", `⚠️ ${data.message || "An error occurred with PassGuard AI."}`, timeStr);
      }
    } catch (err) {
      if (typingIndicator) typingIndicator.style.display = "none";
      if (btnSend) btnSend.disabled = false;
      appendMessage("assistant", "⚠️ Network connection interrupted. Please try again.", timeStr);
    }
  }

  if (btnSend) {
    btnSend.addEventListener("click", () => sendMessage());
  }

  if (chatInput) {
    chatInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
  }

  // Starter Question Chips
  chipBtns.forEach((chip) => {
    chip.addEventListener("click", () => {
      const question = chip.getAttribute("data-question");
      if (question) {
        sendMessage(question);
      }
    });
  });

  // Clear Chat History
  if (btnClearChat) {
    btnClearChat.addEventListener("click", async () => {
      if (!confirm("Clear this conversation history?")) return;

      try {
        const response = await fetch("/api/assistant/history", {
          method: "DELETE",
          headers: {
            "X-CSRFToken": csrfToken,
            "X-Requested-With": "XMLHttpRequest"
          }
        });
        if (response.ok) {
          // Keep only initial system greeting
          chatFeed.innerHTML = `
            <div class="chat-bubble assistant">
              <strong>Conversation cleared.</strong> Feel free to ask a new question about password security, MFA, or credential hashing.
              <div class="chat-time">System</div>
            </div>
            <div id="typingIndicator" class="typing-indicator" style="display: none;">
              <div class="typing-dot"></div>
              <div class="typing-dot"></div>
              <div class="typing-dot"></div>
            </div>
          `;
          scrollToBottom();
        }
      } catch (err) {
        console.error("Failed to clear chat history:", err);
      }
    });
  }

  // Scroll to bottom on initial load
  scrollToBottom();
});
