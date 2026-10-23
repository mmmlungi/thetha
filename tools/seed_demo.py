"""Fill the dev database with demo data for presentations. Never run in production."""
import os
import random
import secrets
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash  # noqa: E402

from app import create_app  # noqa: E402
from app.db import get_db, utcnow  # noqa: E402
from app.resources import PROVINCES  # noqa: E402

DEMO_PASSWORD = "Demo2026pass"
INTENTS = ["abuse_disclosure"] * 9 + ["protection_order"] * 6 + ["safety_plan"] * 4 + \
          ["sexual_assault"] * 3 + ["financial_abuse"] * 3 + ["online_abuse"] * 2 + \
          ["counselling"] * 3 + ["shelter"] * 2 + ["emergency"] * 2 + ["greeting"] * 5 + ["risk_result"] * 4


def main():
    app = create_app()
    if app.config["ENV_NAME"] == "production":
        sys.exit("Refusing to seed a production database.")
    rng = random.Random(7)  # nosec B311 - demo data, not security
    with app.app_context():
        db, v = get_db(), app.extensions["vault"]
        for name, role in (("counsellor", "counsellor"), ("demo", "survivor")):
            idx = v.blind_index(name)
            if not db.execute("SELECT 1 FROM users WHERE username_index = ?", (idx,)).fetchone():
                db.execute("INSERT INTO users (username_index, alias_enc, password_hash, role, created_at) "
                           "VALUES (?, ?, ?, ?, ?)",
                           (idx, v.encrypt(name, f"alias:{idx}"), generate_password_hash(DEMO_PASSWORD), role, utcnow()))
        demo_id = db.execute("SELECT id FROM users WHERE username_index = ?", (v.blind_index("demo"),)).fetchone()[0]
        if not db.execute("SELECT 1 FROM journal_entries WHERE user_id = ?", (demo_id,)).fetchone():
            for days_ago, kind, text, injuries in [
                (40, "emotional", "He called me useless in front of the children and took my phone.", ""),
                (21, "financial", "He took my SASSA card again and said I can't have money for transport.", ""),
                (9, "physical", "He pushed me into the wardrobe after I asked where he was all night.", "Bruise on left arm"),
                (2, "threats", "He said if I go to the police he will make sure I never see the kids.", ""),
            ]:
                entry = {"date": (date.today() - timedelta(days=days_ago)).isoformat(), "type": kind,
                         "description": text, "location": "Home", "injuries": injuries, "witnesses": ""}
                db.execute("INSERT INTO journal_entries (user_id, payload_enc, created_at) VALUES (?, ?, ?)",
                           (demo_id, v.encrypt_json(entry, f"journal:{demo_id}"), utcnow()))
            plan = {"contacts": "Sister Zanele, neighbour Mrs Dlamini", "code_word": "Are the tomatoes ripe?",
                    "safe_place": "Zanele's house in Soweto", "bag_location": "Under the bed at Mrs Dlamini's",
                    "documents": ["ID / passport", "Birth certificates (yours and children's)", "SASSA card"],
                    "notes": "He works night shift on Thursdays."}
            db.execute("INSERT OR REPLACE INTO safety_plans (user_id, payload_enc, updated_at) VALUES (?, ?, ?)",
                       (demo_id, v.encrypt_json(plan, f"safety:{demo_id}"), utcnow()))

        if db.execute("SELECT COUNT(*) FROM chat_events").fetchone()[0] >= 400:
            db.commit()
            print(f"Demo data ready. Logins: counsellor / {DEMO_PASSWORD}  and  demo / {DEMO_PASSWORD}")
            return
        weights = [9, 3, 14, 12, 4, 5, 4, 2, 8]
        for _ in range(400):
            intent = rng.choice(INTENTS)
            risk = rng.choice(["high", "medium", "medium", "low"]) if intent == "risk_result" else None
            db.execute("INSERT INTO chat_events (day, intent, risk_level, language, province) VALUES (?, ?, ?, ?, ?)",
                       ((date.today() - timedelta(days=rng.randint(0, 29))).isoformat(), intent, risk,
                        rng.choice(["en"] * 6 + ["zu"] * 2 + ["xh", "af", "st"]),
                        rng.choices(PROVINCES, weights)[0]))
        for name, phone, prov, urg in [("Thandi", "0821234567", "Gauteng", "urgent"),
                                       ("", "0739876543", "KwaZulu-Natal", "normal"),
                                       ("Mpho", "0614445555", "Limpopo", "normal")]:
            ref = secrets.token_hex(4).upper()
            payload = {"name": name, "phone": phone, "safe_time": "Weekdays 10:00-12:00",
                       "leave_message": False, "notes": ""}
            db.execute("INSERT INTO callback_requests (ref, payload_enc, province, urgency, created_at) "
                       "VALUES (?, ?, ?, ?, ?)", (ref, v.encrypt_json(payload, f"callback:{ref}"), prov, urg, utcnow()))
        db.commit()
    print(f"Demo data ready. Logins: counsellor / {DEMO_PASSWORD}  and  demo / {DEMO_PASSWORD}")


if __name__ == "__main__":
    main()
