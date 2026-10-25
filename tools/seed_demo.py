"""Fill the dev database with demo data for presentations. Never run in production."""
import hashlib
import io
import os
import random
import secrets
import sys
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash  # noqa: E402

from app import create_app  # noqa: E402
from app.db import get_db, utcnow  # noqa: E402
from app import media  # noqa: E402
from app.resources import PROVINCES  # noqa: E402
from app.security import check_password_policy  # noqa: E402

# Local demos use a known password; a public deployment must choose its own (THETHA_DEMO_PASSWORD),
# otherwise anyone reading the README could log in as counsellor and see real callers' numbers.
DEMO_PASSWORD = os.environ.get("THETHA_DEMO_PASSWORD") or "Demo2026pass"
SHOWN_PASSWORD = "<your chosen password>" if os.environ.get("THETHA_DEMO_PASSWORD") else DEMO_PASSWORD
INTENTS = ["abuse_disclosure"] * 9 + ["protection_order"] * 6 + ["safety_plan"] * 4 + \
          ["sexual_assault"] * 3 + ["financial_abuse"] * 3 + ["online_abuse"] * 2 + \
          ["counselling"] * 3 + ["shelter"] * 2 + ["emergency"] * 2 + ["greeting"] * 5 + ["risk_result"] * 4


def _demo_screenshot() -> bytes:
    """A made-up chat screenshot, so the demo shows evidence without anything graphic."""
    from PIL import Image, ImageDraw
    im = Image.new("RGB", (540, 360), (236, 229, 221))
    d = ImageDraw.Draw(im)
    d.rectangle((0, 0, 540, 54), fill=(7, 94, 84))
    d.text((20, 18), "Mr K (Supervisor)", fill=(255, 255, 255))
    bubbles = [("If you want to keep this job you'll be nicer to me.", 80),
               ("Come to my office after your shift. Alone.", 160),
               ("Don't tell HR. Nobody will believe you anyway.", 240)]
    for text, y in bubbles:
        d.rounded_rectangle((20, y, 470, y + 56), radius=12, fill=(255, 255, 255))
        d.text((36, y + 20), text, fill=(30, 30, 30))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def _seed_workplace_entry(db, v, demo_id):
    entry = {"date": (date.today() - timedelta(days=5)).isoformat(), "type": "sexual harassment",
             "setting": "workplace", "description": "My supervisor sent me these messages after I refused to "
             "go for drinks with him. The next day he moved me to night shift.",
             "location": "Warehouse, Germiston", "injuries": "", "witnesses": "Thandeka saw the messages",
             "employer": "Example Logistics (demo)", "perpetrator_role": "manager or supervisor",
             "reported": "yes, to HR", "report_ref": "HR-2026-118", "work_impact": "Moved to night shift, lost overtime"}
    cur = db.execute("INSERT INTO journal_entries (user_id, payload_enc, created_at) VALUES (?, ?, ?)",
                     (demo_id, v.encrypt_json(entry, f"journal:{demo_id}"), utcnow()))
    data = _demo_screenshot()
    name = media.write_encrypted(v, demo_id, data)
    meta = {"name": "whatsapp-screenshot.png", "mime": "image/png", "kind": "image", "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}
    db.execute("INSERT INTO journal_media (entry_id, user_id, stored_name, size, meta_enc, created_at) "
               "VALUES (?, ?, ?, ?, ?, ?)",
               (cur.lastrowid, demo_id, name, len(data), v.encrypt_json(meta, media.meta_ctx(demo_id, name)), utcnow()))


def main():
    app = create_app()
    if app.config["ENV_NAME"] == "production":
        if "--demo-in-production" not in sys.argv:
            sys.exit("Refusing to seed a production database.")
        if not os.environ.get("THETHA_DEMO_PASSWORD"):
            sys.exit("Set THETHA_DEMO_PASSWORD: the default demo password is public in the README.")
        check_password_policy(DEMO_PASSWORD)
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

        if not db.execute("SELECT 1 FROM journal_media WHERE user_id = ?", (demo_id,)).fetchone():
            _seed_workplace_entry(db, v, demo_id)

        if db.execute("SELECT COUNT(*) FROM chat_events").fetchone()[0] >= 400:
            db.commit()
            print(f"Demo data ready. Logins: counsellor / {SHOWN_PASSWORD}  and  demo / {SHOWN_PASSWORD}")
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
    print(f"Demo data ready. Logins: counsellor / {SHOWN_PASSWORD}  and  demo / {SHOWN_PASSWORD}")


if __name__ == "__main__":
    main()
