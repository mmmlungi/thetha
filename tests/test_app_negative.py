"""Negative tests: invalid, malicious or unauthorised requests are rejected safely."""
import pytest

from conftest import PASSWORD, add_journal, chat, csrf, login, make_counsellor, register

pytestmark = pytest.mark.negative


# ---------------------------------------------------------------- input validation
@pytest.mark.parametrize("payload", [{}, {"message": ""}, {"message": "   "}, {"message": 123},
                                     {"message": ["a"]}, {"message": "x" * 501}])
def test_chat_rejects_invalid_messages(client, payload):
    r = client.post("/api/chat", json=payload, headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 400 and "error" in r.get_json()


def test_chat_rejects_non_json(client):
    r = client.post("/api/chat", data="hello", headers={"X-CSRF-Token": csrf(client)})
    assert r.status_code == 400


def test_chat_rejects_unknown_province(client):
    assert chat(client, "hello", province="Atlantis").status_code == 400


def test_oversized_body_rejected(client):
    r = client.post("/api/chat", data="x" * 70_000, headers={"X-CSRF-Token": csrf(client),
                                                             "Content-Type": "application/json"})
    assert r.status_code == 413


@pytest.mark.parametrize("pw", ["short1", "allletters", "12345678", "password1"])
def test_weak_passwords_rejected(client, pw):
    assert register(client, password=pw).status_code == 400


@pytest.mark.parametrize("name", ["ab", "<script>", "a" * 40, "robert'); DROP TABLE users;--"])
def test_invalid_usernames_rejected(client, name):
    assert register(client, username=name).status_code == 400


def test_duplicate_username_rejected_case_insensitively(client):
    register(client, "Lindiwe")
    client.post("/logout", data={"_csrf": csrf(client)})
    assert register(client, "LINDIWE").status_code == 400


def test_journal_rejects_future_date_and_bad_type(client):
    register(client)
    assert add_journal(client, date="2999-01-01").status_code == 400
    assert add_journal(client, date="not-a-date").status_code == 400
    assert add_journal(client, type="made-up").status_code == 400
    assert add_journal(client, description="").status_code == 400


@pytest.mark.parametrize("phone", ["", "123", "0821234", "+1 555 123 4567", "08212345678", "abcdefghij"])
def test_callback_rejects_invalid_phone(client, phone):
    r = client.post("/callback", data={"_csrf": csrf(client, "/callback"), "phone": phone,
                                       "safe_time": "Now", "province": "Gauteng", "urgency": "normal"})
    assert r.status_code == 400


def test_callback_rejects_invalid_urgency(client):
    r = client.post("/callback", data={"_csrf": csrf(client, "/callback"), "phone": "0821234567",
                                       "safe_time": "Now", "province": "Gauteng", "urgency": "panic"})
    assert r.status_code == 400


# ---------------------------------------------------------------- authentication
def test_wrong_password_rejected(client):
    register(client)
    client.post("/logout", data={"_csrf": csrf(client)})
    assert login(client, password="Wrong1234").status_code == 401


def test_unknown_user_gets_same_message_as_wrong_password(client):
    register(client)
    client.post("/logout", data={"_csrf": csrf(client)})
    a = login(client, "nobody", "Wrong1234").get_data(as_text=True)
    b = login(client, "lindiwe", "Wrong1234").get_data(as_text=True)
    assert "Incorrect username or password" in a and "Incorrect username or password" in b


def test_account_locks_after_repeated_failures(client):
    register(client)
    client.post("/logout", data={"_csrf": csrf(client)})
    for _ in range(5):
        login(client, password="Wrong1234")
    assert login(client).status_code == 429  # correct password still refused while locked


def test_sql_injection_in_login_does_not_bypass_auth(client):
    register(client)
    client.post("/logout", data={"_csrf": csrf(client)})
    for payload in ["' OR '1'='1", "lindiwe'--", "\" OR 1=1 --"]:
        assert login(client, payload, "' OR '1'='1").status_code == 401


def test_open_redirect_blocked(client):
    register(client)
    client.post("/logout", data={"_csrf": csrf(client)})
    token = csrf(client, "/login")
    r = client.post("/login?next=//evil.example.com", data={"_csrf": token, "username": "lindiwe",
                                                             "password": PASSWORD})
    assert "evil.example.com" not in r.headers["Location"]


# ---------------------------------------------------------------- authorisation
@pytest.mark.parametrize("path", ["/journal", "/safety-plan", "/my-data", "/my-data/export", "/counsellor"])
def test_anonymous_users_cannot_access_private_pages(client, path):
    r = client.get(path)
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_survivor_cannot_open_counsellor_dashboard(client):
    register(client)
    assert client.get("/counsellor").status_code == 403


def test_survivor_cannot_close_callbacks(client):
    register(client)
    assert client.post("/counsellor/callback/1/close", data={"_csrf": csrf(client)}).status_code == 403


def test_user_cannot_read_or_delete_another_users_entry(app):
    a, b = app.test_client(), app.test_client()
    register(a, "alice1")
    add_journal(a, description="alice private entry")
    register(b, "bongi1")
    assert "alice private entry" not in b.get("/journal").get_data(as_text=True)
    assert b.post("/journal/1/delete", data={"_csrf": csrf(b, "/journal")}).status_code == 404
    assert "alice private entry" in a.get("/journal").get_data(as_text=True)


def test_delete_my_data_requires_correct_password(app, client):
    register(client)
    add_journal(client)
    r = client.post("/my-data/delete", data={"_csrf": csrf(client, "/my-data"), "password": "Wrong1234"})
    assert r.status_code == 401
    with app.app_context():
        from app.db import get_db
        assert get_db().execute("SELECT COUNT(*) FROM journal_entries").fetchone()[0] == 1


# ---------------------------------------------------------------- CSRF / rate limits / XSS
@pytest.mark.parametrize("path, data", [("/api/chat", None), ("/journal", {}), ("/callback", {}),
                                        ("/login", {"username": "x", "password": "y"})])
def test_post_without_csrf_token_rejected(client, path, data):
    register(client)
    r = client.post(path, json={"message": "hi"}) if data is None else client.post(path, data=data)
    assert r.status_code == 400


def test_forged_csrf_token_rejected(client):
    csrf(client)
    assert client.post("/api/chat", json={"message": "hi"}, headers={"X-CSRF-Token": "forged"}).status_code == 400


def test_chat_rate_limited(make_app):
    app = make_app(RATE_LIMITS={"chat": (3, 60), "login": (10, 300), "register": (5, 3600),
                                "callback": (5, 3600), "write": (60, 300)})
    c = app.test_client()
    token = csrf(c)
    codes = [chat(c, "hello", token=token).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]


def test_xss_in_journal_is_escaped(client):
    register(client)
    add_journal(client, description='<script>alert("x")</script>')
    html = client.get("/journal").get_data(as_text=True)
    assert '<script>alert("x")</script>' not in html
    assert "&lt;script&gt;" in html


def test_xss_in_callback_is_escaped_for_counsellor(app, client):
    client.post("/callback", data={"_csrf": csrf(client, "/callback"), "name": "<img src=x onerror=alert(1)>",
                                   "phone": "0821234567", "safe_time": "Now", "province": "Gauteng",
                                   "urgency": "normal"})
    make_counsellor(app)
    c = app.test_client()
    login(c, "counsel1", "Couns3lPass")
    assert "<img src=x" not in c.get("/counsellor").get_data(as_text=True)


def test_unknown_route_returns_404(client):
    assert client.get("/admin.php").status_code == 404


def test_production_refuses_to_start_without_keys(monkeypatch, tmp_path):
    from app import create_app
    monkeypatch.setenv("THETHA_ENV", "production")
    monkeypatch.delenv("THETHA_MASTER_KEY", raising=False)
    monkeypatch.delenv("THETHA_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app({"DATABASE": str(tmp_path / "p.db")})
