"""
Passwords page routes: ephemeral generator & zero-knowledge masked history.
Enforces zero plain-text retention and user-specific deletion.
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from sqlalchemy import func

from models import db, PasswordCheck
from security.password_generator import generate_curated_suggestions

passwords_bp = Blueprint("passwords", __name__)


@passwords_bp.route("/passwords", methods=["GET"])
@login_required
def passwords_view():
    return render_template("passwords.html", page_title="Password Management")


@passwords_bp.route("/api/passwords/generate", methods=["POST"])
@login_required
def generate_passwords():
    data = request.get_json() or {}
    length = int(data.get("length", 16))
    include_upper = bool(data.get("include_upper", True))
    include_lower = bool(data.get("include_lower", True))
    include_digits = bool(data.get("include_digits", True))
    include_special = bool(data.get("include_special", True))

    pepper = current_app.config["PEPPER"]

    # Gather user's existing HMACs to avoid recommending already checked passwords
    user_checks = PasswordCheck.query.filter_by(user_id=current_user.id).with_entities(PasswordCheck.password_hmac).all()
    user_existing_hmacs = {c.password_hmac for c in user_checks}

    suggestions = generate_curated_suggestions(
        count=10,
        length=length,
        include_upper=include_upper,
        include_lower=include_lower,
        include_digits=include_digits,
        include_special=include_special,
        user_existing_hmacs=user_existing_hmacs,
        user_id=current_user.id,
        pepper=pepper
    )

    return jsonify({
        "status": "success",
        "suggestions": suggestions
    })


@passwords_bp.route("/api/passwords/history", methods=["GET"])
@login_required
def get_password_history():
    """
    Returns masked password records for current user with frequency count and date.
    Zero plain-text is ever read or returned.
    """
    # Group by password_hmac to calculate 'number of times checked'
    hmac_counts = (
        db.session.query(
            PasswordCheck.password_hmac,
            func.count(PasswordCheck.id).label("times_checked"),
            func.max(PasswordCheck.checked_at).label("latest_check"),
            func.max(PasswordCheck.id).label("latest_id")
        )
        .filter(PasswordCheck.user_id == current_user.id)
        .group_by(PasswordCheck.password_hmac)
        .order_by(func.max(PasswordCheck.checked_at).desc())
        .all()
    )

    history = []
    for hmac_val, times, latest_dt, latest_id in hmac_counts:
        rec = db.session.get(PasswordCheck, latest_id)
        if rec:
            history.append({
                "id": rec.id,
                "hmac": hmac_val,
                "masked_preview": rec.masked_preview,
                "length": rec.length,
                "score": rec.score,
                "level": rec.level,
                "times_checked": times,
                "checked_at": latest_dt.strftime("%Y-%m-%d %H:%M") if latest_dt else ""
            })

    return jsonify({
        "status": "success",
        "history": history
    })


@passwords_bp.route("/api/passwords/history/<int:check_id>", methods=["DELETE"])
@login_required
def delete_history_item(check_id):
    rec = PasswordCheck.query.filter_by(id=check_id, user_id=current_user.id).first()
    if not rec:
        return jsonify({"status": "error", "message": "Record not found"}), 404

    # Delete all instances of this specific HMAC for this user
    target_hmac = rec.password_hmac
    deleted_count = PasswordCheck.query.filter_by(user_id=current_user.id, password_hmac=target_hmac).delete()
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Removed {deleted_count} record(s) from check history."
    })


@passwords_bp.route("/api/passwords/history/clear", methods=["DELETE"])
@login_required
def clear_all_history():
    deleted_count = PasswordCheck.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()

    return jsonify({
        "status": "success",
        "message": f"Successfully cleared all {deleted_count} history records."
    })
