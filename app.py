"""
PassGuard Application Factory & Server Entry Point.
Configures security headers, session policies, CSRF protection, and route blueprints.
"""

import os
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, session, redirect, url_for, flash, request
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect, CSRFError

from config import Config
from models import db, User

csrf = CSRFProtect()
login_manager = LoginManager()


def create_app(config_class=Config) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to access your security console."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Session inactivity enforcement (30 minutes)
    @app.before_request
    def check_session_timeout():
        session.permanent = True
        if current_user.is_authenticated:
            now_ts = datetime.now(timezone.utc).timestamp()
            last_active = session.get("last_active")
            if last_active and (now_ts - last_active > 1800):  # 30 minutes
                session.clear()
                flash("Your session has timed out due to 30 minutes of inactivity.", "info")
                return redirect(url_for("auth.login"))
            session["last_active"] = now_ts

    # Security headers on every response
    @app.after_request
    def apply_security_headers(response):
        # Strict Content-Security-Policy permitting Chart.js CDN and Google Fonts
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.pwnedpasswords.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

    # Error Handlers
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        if request.is_json:
            return jsonify({"status": "error", "message": "CSRF verification failed. Please refresh."}), 400
        flash("Your security session expired. Please resubmit the form.", "danger")
        return redirect(url_for("auth.login"))

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("base.html", page_title="Page Not Found", error_code=404), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template("base.html", page_title="Internal Error", error_code=500), 500

    # Register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.checker import checker_bp
    from routes.passwords import passwords_bp
    from routes.assistant import assistant_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(checker_bp)
    app.register_blueprint(passwords_bp)
    app.register_blueprint(assistant_bp)

    with app.app_context():
        db.create_all()

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
