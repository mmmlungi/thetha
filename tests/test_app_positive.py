"""Positive tests: the app does what it should for valid, expected use."""
import json

import pytest

from conftest import PASSWORD, add_journal, chat, csrf, login, make_counsellor, register

pytestmark = pytest.mark.positive


def test_home_page_loads_with_quick_exit_and_emergency_numbers(client):
    html = client.get("/").get_data(as_text=True)
    assert 'id="quick-exit"' in html
    assert "10111" in html and "0800 428 428" in html


def test_chat_api_replies(client):
    r = chat(client, "my partner hits me")
    assert r.status_code == 200
    body = r.get_json()
    assert body["intent"] == "abuse_disclosure"
    assert "not your fault" in body["text"]
    assert "state" not in body


def test_chat_quick_reply_alias(client):
    assert chat(client, "Make a safety plan").get_json()["intent"] == "safety_plan"


def test_multi_turn_risk_check_over_http(client):
    token = csrf(client)
    chat(client, "am i safe", token=token)
    for _ in range(6):
        r = chat(client, "yes", token=token)
    assert r.get_json()["risk_level"] == "high"


def test_chat_records_only_anonymous_event(app, client):
    chat(client, "my partner hits me", province="Gauteng")
    with app.app_context():
        from app.db import get_db
        row = get_db().execute("SELECT * FROM chat_events").fetchone()
    assert row["intent"] == "abuse_disclosure" and row["province"] == "Gauteng"
    assert "hits" not in json.dumps(dict(row))


def test_register_and_login(client):
    assert register(client).status_code == 302
    client.post("/logout", data={"_csrf": csrf(client)})
    r = login(client)
    assert r.status_code == 302 and r.headers["Location"].endswith("/journal")


def test_journal_entry_saved_and_read_back_decrypted(client):
    register(client)
    assert add_journal(client, description="Slapped me after church").status_code == 302
    html = client.get("/journal").get_data(as_text=True)
    assert "Slapped me after church" in html


def test_delete_own_journal_entry(client):
    register(client)
    add_journal(client, description="to be deleted")
    r = client.post("/journal/1/delete", data={"_csrf": csrf(client, "/journal")})
    assert r.status_code == 302
    assert "to be deleted" not in client.get("/journal").get_data(as_text=True)


def test_safety_plan_saved_and_updated(client):
    register(client)
    token = csrf(client, "/safety-plan")
    client.post("/safety-plan", data={"_csrf": token, "code_word": "pineapple",
                                      "documents": ["ID / passport", "SASSA card"]})
    client.post("/safety-plan", data={"_csrf": token, "code_word": "mango"})
    html = client.get("/safety-plan").get_data(as_text=True)
    assert "mango" in html and "pineapple" not in html


def test_export_my_data(client):
    register(client)
    add_journal(client, description="exported entry")
    r = client.get("/my-data/export")
    assert r.status_code == 200
    assert "attachment" in r.headers["Content-Disposition"]
    assert r.get_json()["journal"][0]["description"] == "exported entry"


def test_delete_all_my_data(app, client):
    register(client)
    add_journal(client)
    r = client.post("/my-data/delete", data={"_csrf": csrf(client, "/my-data"), "password": PASSWORD})
    assert r.status_code == 302
    with app.app_context():
        from app.db import get_db
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM journal_entries").fetchone()[0] == 0


def test_callback_request_and_counsellor_sees_decrypted_number(app, client):
    r = client.post("/callback", data={"_csrf": csrf(client, "/callback"), "name": "Thandi",
                                       "phone": "082 123 4567", "safe_time": "Mornings",
                                       "province": "KwaZulu-Natal", "urgency": "urgent"})
    assert r.status_code == 200 and "reference" in r.get_data(as_text=True)
    make_counsellor(app)
    c = app.test_client()
    login(c, "counsel1", "Couns3lPass")
    html = c.get("/counsellor").get_data(as_text=True)
    assert "0821234567" in html and "Thandi" in html


def test_counsellor_closes_callback(app, client):
    client.post("/callback", data={"_csrf": csrf(client, "/callback"), "phone": "0821234567",
                                   "safe_time": "Now", "province": "Gauteng", "urgency": "normal"})
    make_counsellor(app)
    c = app.test_client()
    login(c, "counsel1", "Couns3lPass")
    assert c.post("/counsellor/callback/1/close", data={"_csrf": csrf(c, "/counsellor")}).status_code == 302
    assert "0821234567" not in c.get("/counsellor").get_data(as_text=True)


def test_dashboard_shows_anonymous_statistics(app, client):
    chat(client, "my partner hits me", province="Limpopo")
    make_counsellor(app)
    c = app.test_client()
    login(c, "counsel1", "Couns3lPass")
    html = c.get("/counsellor").get_data(as_text=True)
    assert "Limpopo" in html and "abuse disclosure" in html


def test_quick_exit_clears_session(client):
    register(client)
    assert client.post("/quick-exit").status_code == 204
    assert client.get("/journal").status_code == 302  # logged out


def test_purge_removes_expired_closed_callbacks(app):
    with app.app_context():
        from app.db import get_db, purge_expired
        db = get_db()
        db.execute("INSERT INTO callback_requests (ref, payload_enc, province, urgency, status, created_at, closed_at) "
                   "VALUES ('OLD1', 'v1:x', 'Gauteng', 'normal', 'closed', '2020-01-01', '2020-01-02T00:00:00+00:00')")
        db.commit()
        assert purge_expired(30, 365)["callbacks"] == 1


def test_resources_page(client):
    html = client.get("/resources").get_data(as_text=True)
    assert "Magistrate" in html and "Childline" in html
