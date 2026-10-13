"""
PassGuard AI Assistant routes.
Interacts with the Anthropic Claude API with strict security controls:
- PassGuard AI cyber security system prompt
- Zero-knowledge HMAC token redaction
- 20 messages / hour per-user rate limiting
- 50 messages conversation history retention
- Graceful API key and connection error handling
"""

import os
import re
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user

from models import db, ChatMessage, PasswordCheck
from security.hasher import generate_password_hmac

assistant_bp = Blueprint("assistant", __name__)

SYSTEM_PROMPT = (
    "You are PassGuard AI, an elite cyber security assistant embedded in the PassGuard "
    "Password Strength Checker platform. Your mission is to provide clear, actionable, "
    "and professional guidance on password security, credential hashing (Argon2, bcrypt), "
    "password managers, multi-factor authentication (2FA/MFA), phishing detection, "
    "data breaches, safe password policies at work, and how to utilize the PassGuard app.\n\n"
    "Crucial rules:\n"
    "1. NEVER ask the user to type or reveal a real password.\n"
    "2. If the user appears to share a password or credential, immediately warn them of the security risk and never repeat or echo the credential.\n"
    "3. Politely decline questions that are completely unrelated to cybersecurity, credential hygiene, or account protection.\n"
    "4. Format answers with clear headings, bullet points, and high readability."
)


def redact_user_message(message: str, user_id: int, pepper: str) -> str:
    """
    Scans the user message against their previously checked password HMACs.
    Any token matching an existing checked password HMAC is replaced with [REDACTED].
    """
    user_hmacs = {
        c.password_hmac
        for c in PasswordCheck.query.filter_by(user_id=user_id).with_entities(PasswordCheck.password_hmac).all()
    }
    if not user_hmacs:
        return message

    redacted = message

    # Check if the whole message matches
    if generate_password_hmac(message.strip(), user_id, pepper) in user_hmacs:
        return "[REDACTED]"

    # Extract non-whitespace tokens and check individual words
    tokens = set(re.findall(r"\S+", message))
    for token in tokens:
        cleaned_token = token.strip(".,!?;:\"'()[]{}")
        if len(cleaned_token) >= 4:
            token_hmac = generate_password_hmac(cleaned_token, user_id, pepper)
            if token_hmac in user_hmacs:
                redacted = re.sub(re.escape(cleaned_token), "[REDACTED]", redacted)

    return redacted


@assistant_bp.route("/assistant", methods=["GET"])
@login_required
def assistant_view():
    history = (
        ChatMessage.query.filter_by(user_id=current_user.id)
        .order_by(ChatMessage.created_at.asc())
        .limit(50)
        .all()
    )
    return render_template(
        "assistant.html",
        page_title="AI Security Assistant",
        chat_history=[m.to_dict() for m in history]
    )


@assistant_bp.route("/api/assistant/chat", methods=["POST"])
@login_required
def send_chat_message():
    data = request.get_json() or {}
    user_text = (data.get("message") or "").strip()

    if not user_text:
        return jsonify({"status": "error", "message": "Message cannot be empty."}), 400

    # 1. Rate limiting: Max 20 messages per hour per user
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    hourly_count = ChatMessage.query.filter(
        ChatMessage.user_id == current_user.id,
        ChatMessage.role == "user",
        ChatMessage.created_at >= one_hour_ago
    ).count()

    if hourly_count >= 20:
        return jsonify({
            "status": "error",
            "message": "Rate limit exceeded: You can send a maximum of 20 messages per hour. Please try again later."
        }), 429

    # 2. Redaction of user passwords
    pepper = current_app.config["PEPPER"]
    sanitized_text = redact_user_message(user_text, current_user.id, pepper)

    # 3. Save user message to database
    user_msg = ChatMessage(
        user_id=current_user.id,
        role="user",
        content=sanitized_text
    )
    db.session.add(user_msg)
    db.session.commit()

    # 4. Check for Anthropic API Key
    api_key = current_app.config.get("ANTHROPIC_API_KEY")
    if not api_key:
        reply_text = (
            "**PassGuard AI is in offline demo mode**.\n\n"
            "To connect to the Anthropic Claude API, please add your `ANTHROPIC_API_KEY` to the `.env` file and restart the application.\n\n"
            "*Security Tip:* Remember to always use multi-factor authentication (MFA) and a reliable password manager like Bitwarden or 1Password for end-to-end credential security."
        )
        ai_msg = ChatMessage(user_id=current_user.id, role="assistant", content=reply_text)
        db.session.add(ai_msg)
        db.session.commit()
        return jsonify({
            "status": "success",
            "reply": reply_text,
            "created_at": ai_msg.created_at.strftime("%H:%M")
        })

    # 5. Fetch recent conversation context (last 10 messages)
    recent_db_msgs = (
        ChatMessage.query.filter_by(user_id=current_user.id)
        .order_by(ChatMessage.created_at.desc())
        .limit(10)
        .all()
    )
    recent_db_msgs.reverse()

    claude_messages = []
    for msg in recent_db_msgs:
        claude_messages.append({
            "role": "user" if msg.role == "user" else "assistant",
            "content": msg.content
        })

    # 6. Call Anthropic Claude API
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=800,
            system=SYSTEM_PROMPT,
            messages=claude_messages
        )
        reply_text = response.content[0].text
    except Exception as e:
        reply_text = (
            f"PassGuard AI encountered a connection notice: {str(e)}.\n\n"
            "Please ensure your API key is valid and that outbound internet access is permitted."
        )

    # 7. Persist AI response
    ai_msg = ChatMessage(user_id=current_user.id, role="assistant", content=reply_text)
    db.session.add(ai_msg)

    # 8. Prune history to 50 messages per user
    total_messages = ChatMessage.query.filter_by(user_id=current_user.id).count()
    if total_messages > 50:
        excess = total_messages - 50
        oldest_ids = [
            m.id
            for m in ChatMessage.query.filter_by(user_id=current_user.id)
            .order_by(ChatMessage.created_at.asc())
            .limit(excess)
            .all()
        ]
        if oldest_ids:
            ChatMessage.query.filter(ChatMessage.id.in_(oldest_ids)).delete(synchronize_session=False)

    db.session.commit()

    return jsonify({
        "status": "success",
        "reply": reply_text,
        "created_at": ai_msg.created_at.strftime("%H:%M")
    })


@assistant_bp.route("/api/assistant/history", methods=["DELETE"])
@login_required
def clear_chat_history():
    deleted_count = ChatMessage.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return jsonify({
        "status": "success",
        "message": f"Cleared {deleted_count} messages from conversation history."
    })
