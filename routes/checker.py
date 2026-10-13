"""
Password Checker routes and analysis API.
Supports live analysis, zero-knowledge HMAC reuse detection,
saving check results, and k-anonymity HIBP breach queries.
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user

from models import db, PasswordCheck
from security.hasher import generate_password_hmac, mask_password
from security.strength_engine import analyze_password_strength
from security.hibp import check_hibp_breach

checker_bp = Blueprint("checker", __name__)


@checker_bp.route("/checker", methods=["GET"])
@login_required
def checker_view():
    return render_template("checker.html", page_title="Password Checker")


@checker_bp.route("/api/checker/analyze", methods=["POST"])
@login_required
def analyze_password():
    data = request.get_json() or {}
    password = data.get("password", "")

    if not password:
        return jsonify(analyze_password_strength(""))

    pepper = current_app.config["PEPPER"]
    pwd_hmac = generate_password_hmac(password, current_user.id, pepper)

    # Check reuse against user's prior check history
    prior_check = PasswordCheck.query.filter_by(
        user_id=current_user.id,
        password_hmac=pwd_hmac
    ).first()
    is_reused = prior_check is not None

    result = analyze_password_strength(
        password=password,
        user_name=current_user.full_name,
        user_email=current_user.email,
        is_reused=is_reused
    )

    result["masked_preview"] = mask_password(password)
    return jsonify(result)


@checker_bp.route("/api/checker/save", methods=["POST"])
@login_required
def save_password_check():
    data = request.get_json() or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"status": "error", "message": "Password cannot be empty"}), 400

    pepper = current_app.config["PEPPER"]
    pwd_hmac = generate_password_hmac(password, current_user.id, pepper)

    prior_check = PasswordCheck.query.filter_by(
        user_id=current_user.id,
        password_hmac=pwd_hmac
    ).first()
    is_reused = prior_check is not None

    result = analyze_password_strength(
        password=password,
        user_name=current_user.full_name,
        user_email=current_user.email,
        is_reused=is_reused
    )

    masked = mask_password(password)

    # Commit record to history without ever saving plaintext
    new_check = PasswordCheck(
        user_id=current_user.id,
        password_hmac=pwd_hmac,
        masked_preview=masked,
        length=len(password),
        score=result["score"],
        level=result["level"],
        common_flag=result["is_common"],
        reused_flag=is_reused,
        breached_flag=False
    )
    db.session.add(new_check)
    db.session.commit()

    return jsonify({
        "status": "success",
        "check_id": new_check.id,
        "result": result,
        "masked_preview": masked,
        "message": "Password evaluation recorded securely."
    })


@checker_bp.route("/api/checker/hibp", methods=["POST"])
@login_required
def hibp_check():
    data = request.get_json() or {}
    password = data.get("password", "")
    check_id = data.get("check_id")

    if not password:
        return jsonify({"status": "error", "message": "Password cannot be empty"}), 400

    is_breached, breach_count = check_hibp_breach(password)

    if check_id:
        check_rec = PasswordCheck.query.filter_by(id=check_id, user_id=current_user.id).first()
        if check_rec and is_breached:
            check_rec.breached_flag = True
            db.session.commit()

    return jsonify({
        "status": "success",
        "is_breached": is_breached,
        "breach_count": breach_count
    })
