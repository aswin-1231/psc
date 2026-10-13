# PassGuard — Cyber Security Password Suite

PassGuard is an enterprise-grade cyber security web application for evaluating password entropy, enforcing resilient authentication policies, discovering credential breach exposure via k-anonymity, detecting credential reuse in zero-knowledge, and consulting an AI cyber security assistant.

---

## 🛡️ Key Features

- **Advanced Password Strength Engine (0–100 Score)**:
  - Consolidates regex checks into a single source of truth (`security/strength_engine.py` and `static/js/strength.js`).
  - Evaluates length (12+ recommended, 16+ excellent), character diversity, and Shannon entropy (bits).
  - Simulates offline GPU cluster crack times (10¹⁰ hashes/sec benchmark).
  - Penalizes sequences (`123`, `abc`), keyboard walks (`qwerty`, `asdf`), repeats, leetspeak (`P@ssw0rd`), and personal information (name/email).
  - Categorizes into **Weak (0–39)**, **Medium (40–69)**, and **Strong (70–100)**.
- **Top 10,000 Common Passwords Filter**:
  - Replaces arbitrary lists with an authentic SecLists 10,000 top breached dictionary loaded into memory for instant $O(1)$ set lookups.
  - Hard-caps breached/common passwords to $\le 10$ points (Weak).
- **Three Distinct Status Flags**:
  - **Common**: Present in the top 10,000 common passwords dictionary.
  - **Reused**: Evaluated previously by this user account.
  - **Available**: Unique and not previously tested by the user.
- **Have I Been Pwned (HIBP) k-Anonymity Integration**:
  - Verifies breach exposure by transmitting only the first 5 characters of the SHA-1 hash to the HIBP range API; the plain text is never exposed over the wire.
- **Zero-Knowledge Password Reuse Detection**:
  - Detects duplicate password evaluations without storing plain-text passwords.
  - Hashes passwords using HMAC-SHA256 keyed with a server-side `PEPPER` and `user_id`.
- **Cryptographically Secure Generator & Memorable Passphrases**:
  - Generates 12–32 character high-entropy passwords using Python's `secrets` module.
  - Produces human-memorable EFF-style passphrases (e.g., `Maple-River-Quartz-42!`).
  - Verified strong ($\ge 70$), not common, and not reused before display.
  - Generated suggestions are ephemeral and never saved to the database.
- **PassGuard AI Security Assistant**:
  - Powered by Anthropic's Claude API with a dedicated cybersecurity persona.
  - Automatically scans user prompts against stored HMACs to replace passwords with `[REDACTED]`.
  - Rate-limited to 20 messages per hour per user, retaining the last 50 messages in conversation history.
  - Graceful fallback when an API key is not configured.
- **Security Dashboard & Chart.js Visualizations**:
  - Stat cards with 60fps number count-up animations for total checks, strong, medium, weak, breached, and reused counters.
  - Doughnut distribution chart and 7-day / 30-day timeline line chart.
  - Recent activity table showing masked previews (`P••••••••••!`), length, score, level badge, and status flags.
  - Displays personal user counts alongside platform-wide anonymous aggregate totals.
- **Authentication & Defense-in-Depth**:
  - Account passwords hashed using Argon2id (`time_cost=2`, `memory_cost=65536`, `parallelism=4`).
  - 5-failed-attempt / 5-minute brute-force account lockout.
  - Generic error messages (*"Invalid email or password"*) preventing username enumeration.
  - Session timeout after 30 minutes of inactivity.
  - CSRF protection across all forms and JSON endpoints via Flask-WTF.
  - Hardened HTTP response headers: Content-Security-Policy, X-Frame-Options (`DENY`), X-Content-Type-Options (`nosniff`), Referrer-Policy.
- **Cyberpunk Dark & Accessible Light Design System**:
  - Dark navy (`#07111f`) foundation, glassmorphism cards, cyan (`#38bdf8`) to purple (`#8b5cf6`) accents, glowing input states, and responsive layouts (360px to 1440px).
  - Theme preference persisted in `localStorage`.
  - Full compliance with `prefers-reduced-motion` and WCAG AA contrast standards.

---

## 📂 Project Architecture

```
PSC/
├── .env                              # Local environment variables & secrets (git-ignored)
├── .env.example                      # Environment template
├── .gitignore                        # Git exclusion rules
├── requirements.txt                  # Python dependencies
├── seed.py                           # Database seeder (creates demo account & sample checks)
├── app.py                            # Flask application factory & security headers
├── config.py                         # App configuration
├── models.py                         # SQLAlchemy database models (User, PasswordCheck, ChatMessage)
├── README.md                         # Documentation & security report
├── security/
│   ├── __init__.py
│   ├── hasher.py                     # Argon2id hashing & peppered HMAC reuse tokens
│   ├── common_passwords.py           # Top-10,000 dictionary loader & O(1) set lookup
│   ├── top_10000_passwords.txt       # Top 10,000 common passwords dictionary
│   ├── strength_engine.py            # 0-100 score engine, entropy, crack time & penalties
│   ├── password_generator.py         # Secrets module generator & memorable passphrases
│   └── hibp.py                       # HIBP k-Anonymity SHA-1 API client
├── routes/
│   ├── __init__.py
│   ├── auth.py                       # Sign up, sign in, lockout, logout
│   ├── dashboard.py                  # Dashboard metrics, Chart.js timeline & distribution
│   ├── checker.py                    # Strength evaluation, save check, HIBP range check
│   ├── passwords.py                  # Passwords generator & masked history APIs
│   └── assistant.py                  # PassGuard AI chat, HMAC redaction, rate limiting
├── templates/
│   ├── base.html                     # App shell: Collapsible sidebar, topbar, theme switch, toasts
│   ├── login.html                    # Sign In page (show/hide password, remember me)
│   ├── signup.html                   # Sign Up page (live strength meter gate, score >= 70)
│   ├── dashboard.html                # Metrics cards, Chart.js charts, recent activity table
│   ├── checker.html                  # Strength meter, 5-rule checklist, entropy, HIBP button
│   ├── passwords.html                # Available generator & Already Used history panels
│   └── assistant.html                # PassGuard AI chat interface & quick starter chips
└── static/
    ├── css/
    │   └── styles.css                # CSS design system, dark navy, glassmorphism, animations
    └── js/
        ├── theme.js                  # Theme persistence via localStorage
        ├── strength.js               # Unified regexes, 300ms debounce, client live score preview
        ├── dashboard.js              # Chart.js initialization, count-ups, range toggle
        ├── checker.js                # Debounced checker, single toast on click, HIBP handler
        ├── passwords.js              # Generator slider, copy animations, history deletion
        └── assistant.js              # Chat feed, auto-scroll, typing indicator, starter chips
```

---

## 🚀 Setup Instructions

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Git

### 2. Windows Setup (PowerShell / Command Prompt)

```powershell
# Navigate into the project directory
cd c:\Users\DELL\Desktop\PSC

# Create a virtual environment (if not already present)
python -m venv .venv

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Create .env from template if not present
cp .env.example .env

# Generate random SECRET_KEY and PEPPER in .env (if not set)
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32)); print('PEPPER=' + secrets.token_hex(32))"

# Seed the database with demo account and sample evaluation history
python seed.py

# Run the Flask server
python app.py
```

### 3. Linux / macOS Setup (Bash / Zsh)

```bash
# Navigate to project directory
cd /path/to/PSC

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Seed database
python3 seed.py

# Run server
python3 app.py
```

Open your browser at **`http://127.0.0.1:5000`**.

---

## 🔑 Demo Account Credentials

| Field | Value |
|---|---|
| **Email** | `demo@passguard.local` |
| **Password** | `PassGuard#Demo2026!` |

---

## 🤖 Obtaining and Configuring the Anthropic API Key

PassGuard AI works with the Anthropic Claude API:
1. Create an account at [console.anthropic.com](https://console.anthropic.com/).
2. Navigate to **API Keys** and generate a new key (`sk-ant-...`).
3. Add the key to your `.env` file:
   ```ini
   ANTHROPIC_API_KEY=sk-ant-api03-...
   ```
4. Restart the Flask application.
5. *Note:* If `ANTHROPIC_API_KEY` is blank or unconfigured, PassGuard AI operates in an offline demonstration mode with built-in cybersecurity guidance and zero crashes.

---

## 🔐 Security Design (For Viva / Project Report)

### 1. Account Password Hashing (Argon2id)
Account passwords are never stored in plain text. PassGuard utilizes **Argon2id** (via `argon2-cffi`), the winner of the Password Hashing Competition (PHC) and recommended by OWASP:
- **Memory-Hardness**: Configured with a 64 MB (`memory_cost=65536`) footprint, preventing attackers from conducting high-throughput attacks using GPUs or ASICs.
- **Time-Cost**: `time_cost=2` iterations with `parallelism=4` threads.
- **Side-Channel Mitigation**: Argon2id combines Argon2d (data-dependent memory access for GPU resistance) and Argon2i (data-independent memory access for side-channel cache attack resistance).

### 2. Zero-Knowledge Password Reuse Detection (Peppered HMAC-SHA256)
A classic flaw in password checkers is storing checked passwords in plain text or using a simple hash that allows dictionary rainbow table inversion. PassGuard solves this with **HMAC-SHA256 user-isolated tokens**:
- A cryptographically random server secret (`PEPPER`) is loaded from `.env`.
- For user $U_i$ and candidate password $P$, an isolated key is derived:
  $$K_{U_i} = \text{HMAC-SHA256}(\text{PEPPER}, \text{str}(U_i))$$
- The stored reuse token is:
  $$T = \text{HMAC-SHA256}(K_{U_i}, P)$$
- **Benefits**:
  1. Even if the database is leaked, an attacker cannot reverse $T$ to recover $P$ without knowing the separate server `PEPPER`.
  2. Because $K_{U_i}$ depends on `user_id`, two users checking the identical password will have completely different HMAC tokens, preventing cross-account linkage or correlation attacks.
  3. Checked password history displays only masked strings (`P••••••••••!`).

### 3. Have I Been Pwned k-Anonymity Privacy
When querying the Have I Been Pwned database:
- The SHA-1 hash of the password is calculated locally: `SHA1(P)`.
- Only the first 5 hexadecimal characters (the routing prefix) are sent to `https://api.pwnedpasswords.com/range/{prefix}`.
- HIBP returns ~500–1,000 hash suffixes matching that prefix.
- PassGuard searches the returned list client-side / server-side for the remaining 35 characters.
- **Result**: The third-party API never learns the user's password or the full hash.

### 4. Brute-Force & Session Protections
- **Account Lockout**: After 5 failed password attempts, the user account is locked for 5 minutes (`lock_until = utcnow() + 5 min`).
- **Timing & Enumeration Resistance**: Authentication queries always return a generic *"Invalid email or password"* message.
- **Session Security**: Session cookies are configured with `HttpOnly=True` (inaccessible to JavaScript), `SameSite='Lax'` (mitigating Cross-Site Request Forgery), and automatically time out after 30 minutes of inactivity.

---

## 🧪 Verified Browser Test Results

End-to-end automated testing verified all user journeys:
1. **Sign Up Gate**: Enforces strong password score $\ge 70$; rejects weak inputs with visual shaking and clear guidance.
2. **Dashboard Analytics**: Animated count-ups, dynamic Chart.js timeline, doughnut breakdown, and masked activity table.
3. **Password Checker**: 300ms debouncing, live entropy & crack-time calculation, single-alert on submit, and 3 status flags (Common / Reused / Available).
4. **Password Generator**: 10 verified strong suggestions, memorable passphrases, length sliders, and "Copied!" feedback.
5. **AI Assistant**: PassGuard AI persona, message auto-scroll, starter chips, rate limiting, and HMAC password redaction.
6. **Dark & Light Themes**: Accessible high-contrast toggle with `localStorage` persistence.
7. **Mobile Viewport**: Fully responsive at 375px mobile width.
8. **Lockout Verification**: 5 consecutive incorrect logins trigger HTTP 429 and temporary account lockout.
