"""
Dashboard routes and analytics API endpoints.
Provides aggregated personal stats, anonymous platform-wide totals,
and timeline metrics for Chart.js.
"""

from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy import func

from models import db, PasswordCheck

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def dashboard_view():
    recent_checks = (
        PasswordCheck.query.filter_by(user_id=current_user.id)
        .order_by(PasswordCheck.checked_at.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "dashboard.html",
        page_title="Security Dashboard",
        recent_checks=recent_checks
    )


@dashboard_bp.route("/api/dashboard/stats", methods=["GET"])
@login_required
def dashboard_stats():
    # User's personal counts
    user_checks = PasswordCheck.query.filter_by(user_id=current_user.id)
    user_total = user_checks.count()
    user_strong = user_checks.filter_by(level="strong").count()
    user_medium = user_checks.filter_by(level="medium").count()
    user_weak = user_checks.filter_by(level="weak").count()
    user_common_or_breached = user_checks.filter(
        (PasswordCheck.common_flag == True) | (PasswordCheck.breached_flag == True)
    ).count()
    user_reused = user_checks.filter_by(reused_flag=True).count()

    # Global anonymous counts across all users
    global_total = PasswordCheck.query.count()
    global_strong = PasswordCheck.query.filter_by(level="strong").count()
    global_medium = PasswordCheck.query.filter_by(level="medium").count()
    global_weak = PasswordCheck.query.filter_by(level="weak").count()
    global_common_or_breached = PasswordCheck.query.filter(
        (PasswordCheck.common_flag == True) | (PasswordCheck.breached_flag == True)
    ).count()
    global_reused = PasswordCheck.query.filter_by(reused_flag=True).count()

    return jsonify({
        "status": "success",
        "user_stats": {
            "total_checked": user_total,
            "strong": user_strong,
            "medium": user_medium,
            "weak": user_weak,
            "common_or_breached": user_common_or_breached,
            "reused": user_reused
        },
        "global_stats": {
            "total_checked": global_total,
            "strong": global_strong,
            "medium": global_medium,
            "weak": global_weak,
            "common_or_breached": global_common_or_breached,
            "reused": global_reused
        }
    })


@dashboard_bp.route("/api/dashboard/chart", methods=["GET"])
@login_required
def dashboard_chart_data():
    time_range = request.args.get("range", "7d")
    days = 30 if time_range == "30d" else 7

    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=days - 1)

    # Build date labels
    date_format = "%Y-%m-%d"
    dates = [(start_date + timedelta(days=i)).strftime(date_format) for i in range(days)]
    date_counts = {d: 0 for d in dates}

    # Query checks in range
    checks = (
        PasswordCheck.query.filter(
            PasswordCheck.user_id == current_user.id,
            PasswordCheck.checked_at >= start_date.replace(hour=0, minute=0, second=0)
        )
        .all()
    )

    for c in checks:
        if c.checked_at:
            d_str = c.checked_at.strftime(date_format)
            if d_str in date_counts:
                date_counts[d_str] += 1

    # Distribution counts for current user
    strong_count = PasswordCheck.query.filter_by(user_id=current_user.id, level="strong").count()
    medium_count = PasswordCheck.query.filter_by(user_id=current_user.id, level="medium").count()
    weak_count = PasswordCheck.query.filter_by(user_id=current_user.id, level="weak").count()

    return jsonify({
        "status": "success",
        "timeline": {
            "labels": [d[5:] for d in dates],  # e.g., '10-06'
            "full_dates": dates,
            "counts": [date_counts[d] for d in dates]
        },
        "distribution": {
            "strong": strong_count,
            "medium": medium_count,
            "weak": weak_count
        }
    })
