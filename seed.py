"""
Database Seeding Script for PassGuard.
Creates demo user and populated check history for dashboard charts and metrics.
"""

from datetime import datetime, timezone, timedelta
from app import create_app
from models import db, User, PasswordCheck, ChatMessage
from security.hasher import hash_password, generate_password_hmac, mask_password
from security.strength_engine import analyze_password_strength

app = create_app()

with app.app_context():
    print("Initializing database tables...")
    db.create_all()

    # Check if demo user already exists
    demo_email = "demo@passguard.local"
    demo_user = User.query.filter_by(email=demo_email).first()

    if not demo_user:
        print("Creating demo user: demo@passguard.local ...")
        demo_user = User(
            full_name="Alex Mercer",
            email=demo_email,
            password_hash=hash_password("PassGuard#Demo2026!"),
            failed_login_count=0
        )
        db.session.add(demo_user)
        db.session.commit()
    else:
        print("Demo user already exists.")

    pepper = app.config["PEPPER"]

    # Sample passwords to seed realistic data
    sample_passwords = [
        # (password, days_ago)
        ("PassGuard#Demo2026!", 28),
        ("Winter2024!", 25),
        ("qwerty", 22),
        ("123456", 20),
        ("Dragon#Shield99!", 18),
        ("password", 15),
        ("Maple-River-Quartz-42!", 12),
        ("abc12345", 10),
        ("Vortex-Timber-Haven-88$", 8),
        ("SummerBreak2025!", 6),
        ("K9#mQ!vL2$xR8@pZ", 5),
        ("iloveyou", 4),
        ("letmein", 3),
        ("Citadel-Glacier-99#", 2),
        ("admin", 1),
        ("Quantum-Beacon-44*", 0),
        ("Winter2024!", 0),  # Reused sample
    ]

    # Only seed if no checks exist yet
    existing_checks = PasswordCheck.query.filter_by(user_id=demo_user.id).count()
    if existing_checks == 0:
        print("Seeding sample password evaluation history...")
        seen_hmacs = set()

        for pwd, days_ago in sample_passwords:
            hmac_val = generate_password_hmac(pwd, demo_user.id, pepper)
            is_reused = hmac_val in seen_hmacs
            seen_hmacs.add(hmac_val)

            analysis = analyze_password_strength(
                password=pwd,
                user_name=demo_user.full_name,
                user_email=demo_user.email,
                is_reused=is_reused
            )

            check_time = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=days_ago % 5)

            check_rec = PasswordCheck(
                user_id=demo_user.id,
                password_hmac=hmac_val,
                masked_preview=mask_password(pwd),
                length=len(pwd),
                score=analysis["score"],
                level=analysis["level"],
                common_flag=analysis["is_common"],
                reused_flag=is_reused,
                breached_flag=(analysis["is_common"] or pwd in ["qwerty", "123456", "password"]),
                checked_at=check_time
            )
            db.session.add(check_rec)

        # Seed sample chat messages
        db.session.add(ChatMessage(
            user_id=demo_user.id,
            role="user",
            content="How long should my master password be?",
            created_at=datetime.now(timezone.utc) - timedelta(hours=2)
        ))
        db.session.add(ChatMessage(
            user_id=demo_user.id,
            role="assistant",
            content="A master password should be at least **16 characters long**, or a memorable 4-word passphrase like `Maple-River-Quartz-42!`. Length contributes exponentially to entropy, rendering modern offline brute-force cracking mathematically infeasible.",
            created_at=datetime.now(timezone.utc) - timedelta(hours=2, minutes=-1)
        ))

        db.session.commit()
        print(f"Successfully seeded {len(sample_passwords)} evaluation records and chat history!")
    else:
        print(f"User already has {existing_checks} checks recorded.")

    print("\n=== Demo Account Credentials ===")
    print("Email:    demo@passguard.local")
    print("Password: PassGuard#Demo2026!")
    print("================================")
