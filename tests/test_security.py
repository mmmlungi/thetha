"""Security tests: no sensitive data stored in clear text, crypto misuse is detected."""
import logging
import sqlite3

import pytest

from app.crypto import DecryptionError, Vault, generate_master_key, looks_encrypted
from conftest import PASSWORD, add_journal, chat, csrf, register
from tools.security_scan import run, scan_cleartext

pytestmark = pytest.mark.security

SECRET_TEXT = "Sipho strangled me at 14 Mandela Street"
SECRET_PHONE = "0831112222"


def raw_db(app) -> bytes:
    with open(app.config["DATABASE"], "rb") as fh:
        return fh.read()


def seed(app, client):
    register(client, "nomsa77")
    add_journal(client, description=SECRET_TEXT, location="14 Mandela Street")
    token = csrf(client, "/safety-plan")
    client.post("/safety-plan", data={"_csrf": token, "code_word": "umbrellacode", "contacts": "Aunt 0845556666"})
    client.post("/callback", data={"_csrf": csrf(client, "/callback"), "name": "Nomsa", "phone": SECRET_PHONE,
                                   "safe_time": "after 3pm", "province": "Gauteng", "urgency": "urgent"})
    chat(client, "he strangled me last night")


# ---------------------------------------------------------------- clear-text storage
@pytest.mark.positive
def test_no_sensitive_data_in_raw_database_file(app, client):
    seed(app, client)
    raw = raw_db(app)
    for needle in [SECRET_TEXT, "Mandela", "umbrellacode", SECRET_PHONE, "0845556666", "nomsa77",
                   PASSWORD, "after 3pm", "he strangled me"]:
        assert needle.encode() not in raw, f"'{needle}' stored in clear text!"


@pytest.mark.positive
def test_sensitive_columns_contain_only_ciphertext(app, client):
    seed(app, client)
    conn = sqlite3.connect(app.config["DATABASE"])
    for table, col in [("users", "alias_enc"), ("journal_entries", "payload_enc"),
                       ("safety_plans", "payload_enc"), ("callback_requests", "payload_enc")]:
        values = [r[0] for r in conn.execute(f"SELECT {col} FROM {table}")]  # nosec B608
        assert values and all(looks_encrypted(v) for v in values), table
    assert conn.execute("SELECT password_hash FROM users").fetchone()[0].startswith("scrypt:")
    conn.close()


@pytest.mark.positive
def test_vulnerability_scanner_passes_on_clean_database(app, client):
    seed(app, client)
    findings = run(app.config["DATABASE"], canaries=[SECRET_TEXT, SECRET_PHONE], include_code=False, app=app)
    fails = [f for f in findings if f.level == "FAIL"]
    assert not fails, fails


@pytest.mark.negative
def test_vulnerability_scanner_detects_planted_cleartext(app, client):
    seed(app, client)
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("UPDATE journal_entries SET payload_enc = ? WHERE id = 1", ("I was hit, call 0821234567",))
    conn.execute("UPDATE users SET password_hash = 'Safe2026pass'")
    conn.commit()
    conn.close()
    checks = {f.check for f in scan_cleartext(app.config["DATABASE"], ["I was hit"]) if f.level == "FAIL"}
    assert {"encrypted:journal_entries.payload_enc", "password-hashing", "pii-pattern-scan",
            "raw-file-scan", "canary"} <= checks


@pytest.mark.positive
def test_deleted_data_is_wiped_from_file(app, client):
    register(client)
    add_journal(client)
    client.post("/my-data/delete", data={"_csrf": csrf(client, "/my-data"), "password": PASSWORD})
    # Ciphertext from the deleted rows must not linger in freed pages.
    assert b"v1:" not in raw_db(app)


# ---------------------------------------------------------------- cryptography
@pytest.fixture
def vault():
    return Vault(generate_master_key())


@pytest.mark.positive
def test_encrypt_decrypt_roundtrip_unicode(vault):
    msg = "Ngiyashaywa 😢 — 14 Mandela St"
    assert vault.decrypt(vault.encrypt(msg, "journal:1"), "journal:1") == msg


@pytest.mark.positive
def test_same_plaintext_encrypts_differently_each_time(vault):
    assert vault.encrypt("same", "c") != vault.encrypt("same", "c")


@pytest.mark.negative
def test_tampered_ciphertext_is_rejected(vault):
    token = vault.encrypt("evidence", "journal:1")
    flipped = token[:-3] + ("A" if token[-3] != "A" else "B") + token[-2:]
    with pytest.raises(DecryptionError):
        vault.decrypt(flipped, "journal:1")


@pytest.mark.negative
def test_ciphertext_moved_to_another_user_is_rejected(vault):
    token = vault.encrypt("alice's entry", "journal:1")
    with pytest.raises(DecryptionError):
        vault.decrypt(token, "journal:2")


@pytest.mark.negative
def test_wrong_key_cannot_decrypt(vault):
    token = vault.encrypt("secret", "c")
    with pytest.raises(DecryptionError):
        Vault(generate_master_key()).decrypt(token, "c")


@pytest.mark.negative
@pytest.mark.parametrize("token", ["plain text", "v1:", "v1:!!!notbase64", "v1:AAAA", None, 42])
def test_malformed_tokens_rejected(vault, token):
    with pytest.raises(DecryptionError):
        vault.decrypt(token, "c")


@pytest.mark.negative
@pytest.mark.parametrize("key", ["", "short", "not base64 !!", generate_master_key()[:20]])
def test_invalid_master_keys_rejected(key):
    with pytest.raises(ValueError):
        Vault(key)


@pytest.mark.negative
def test_tampered_row_in_db_shows_warning_not_crash(app, client):
    register(client)
    add_journal(client)
    conn = sqlite3.connect(app.config["DATABASE"])
    token = conn.execute("SELECT payload_enc FROM journal_entries").fetchone()[0]
    conn.execute("UPDATE journal_entries SET payload_enc = ?", (token[:-4] + "AAAA",))
    conn.commit()
    conn.close()
    r = client.get("/journal")
    assert r.status_code == 200 and "could not be decrypted" in r.get_data(as_text=True)


# ---------------------------------------------------------------- transport, headers & logs
@pytest.mark.positive
def test_security_headers_present(client):
    h = client.get("/").headers
    assert "script-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in h["Cache-Control"]
    assert h["Referrer-Policy"] == "no-referrer"


@pytest.mark.positive
def test_session_cookie_flags(client):
    register(client)
    cookie = client.get_cookie("t_sid")
    assert cookie is not None and cookie.http_only and cookie.same_site == "Strict"


@pytest.mark.positive
def test_chat_text_never_in_session_cookie(client):
    chat(client, "he strangled me with a cable")
    assert b"cable" not in client.get_cookie("t_sid").value.encode()


@pytest.mark.positive
def test_logs_redact_phone_numbers_and_emails(app, caplog):
    with caplog.at_level(logging.INFO, logger=app.logger.name):
        app.logger.info("callback for 082 123 4567 / thandi@example.com")
    assert "082 123 4567" not in caplog.text and "thandi@example.com" not in caplog.text
    assert "[phone]" in caplog.text and "[email]" in caplog.text
