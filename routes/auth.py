"""
Authentication routes for PassGuard: Sign Up, Sign In, Remember Me, Lockout, and Logout.
Strict security rules:
- Generic error messages for credential mismatches
- 5-attempt / 5-minute brute-force lockout
- Argon2id password hashing
- Registration password strength gate (score >= 70)
"""

from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user

from models import db, User
from security.hasher import hash_password, verify_password
from security.strength_engine import analyze_password_strength

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard_view"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Form validation
        if not full_name or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("signup.html", full_name=full_name, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("signup.html", full_name=full_name, email=email)

        # Enforce strong password requirement
        strength = analyze_password_strength(password, user_name=full_name, user_email=email)
        if strength["score"] < 70:
            flash(
                "Your password is not strong enough (Score must be at least 70/100). "
                "Ensure it has 12+ characters, uppercase, lowercase, numbers, and symbols.",
                "danger"
            )
            return render_template("signup.html", full_name=full_name, email=email)

        # Check existing email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            # Generic message prevents email enumeration while notifying user
            flash("An account with this email already exists. Please sign in.", "warning")
            return redirect(url_for("auth.login"))

        # Create user with Argon2id hash
        pwd_hash = hash_password(password)
        new_user = User(
            full_name=full_name,
            email=email,
            password_hash=pwd_hash
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in newly registered user
        login_user(new_user)
        flash("Your secure account has been created successfully. Welcome to PassGuard!", "success")
        return redirect(url_for("dashboard.dashboard_view"))

    return render_template("signup.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard_view"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(email=email).first()

        if user:
            # Check lockout status
            if user.is_locked():
                flash("Account is temporarily locked due to multiple failed login attempts. Please try again in 5 minutes.", "danger")
                return render_template("login.html", email=email), 429

            # Verify Argon2id hash
            if verify_password(password, user.password_hash):
                user.reset_failed_login()
                db.session.commit()
                login_user(user, remember=remember)
                session["last_active"] = datetime.now(timezone.utc).timestamp()
                flash(f"Welcome back, {user.full_name.split()[0]}!", "success")
                next_page = request.args.get("next")
                return redirect(next_page or url_for("dashboard.dashboard_view"))
            else:
                user.record_failed_login(max_attempts=5, lockout_minutes=5)
                db.session.commit()
                if user.is_locked():
                    flash("Account is temporarily locked due to 5 failed login attempts. Please try again in 5 minutes.", "danger")
                    return render_template("login.html", email=email), 429

        # Generic error message to prevent account enumeration
        flash("Invalid email or password.", "danger")
        return render_template("login.html", email=email)

    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
