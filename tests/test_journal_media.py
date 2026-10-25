"""Journal evidence files, workplace incidents, printable exports and the installable app."""
import hashlib
import io
import json
import os
import shutil
import sqlite3
import zipfile

import pytest
from PIL import Image

from conftest import PASSWORD, add_journal, chat, csrf, register
from tools.security_scan import scan_media_files

pos = pytest.mark.positive
neg = pytest.mark.negative


def png(color=(200, 30, 30), size=(40, 30)):
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "PNG")
    return buf.getvalue()


PHOTO = png()
VIDEO = b"\x00\x00\x00\x18ftypmp42" + bytes(range(256)) * 4
VOICE = b"\x1a\x45\xdf\xa3" + b"\x42\x86\x81\x01" + bytes(300)


def attach(*items):
    return {"media": [(io.BytesIO(data), name, mime) for data, name, mime in items]}


def stored_files(app):
    d = app.config["MEDIA_DIR"]
    return [os.path.join(d, f) for f in os.listdir(d)] if os.path.isdir(d) else []


def rows(app, sql):
    conn = sqlite3.connect(app.config["DATABASE"])
    out = conn.execute(sql).fetchall()
    conn.close()
    return out


def full_entry(client):
    return add_journal(client, description="He threw my phone at the wall", **attach(
        (PHOTO, "bruise.png", "image/png"), (VIDEO, "clip.mp4", "video/mp4"),
        (VOICE, "voice-note.webm", "audio/webm")))


# ================================================================= positive
@pos
def test_photo_video_and_voice_note_attached_and_viewable(client):
    register(client)
    assert full_entry(client).status_code == 302
    html = client.get("/journal").get_data(as_text=True)
    assert "bruise.png" in html and "<video" in html and "<audio" in html
    photo = client.get("/journal/media/1")
    assert photo.status_code == 200 and photo.data == PHOTO and photo.mimetype == "image/png"
    assert client.get("/journal/media/2").mimetype == "video/mp4"
    assert client.get("/journal/media/3").mimetype == "audio/webm"


@pos
def test_evidence_files_are_encrypted_on_disk(app, client):
    register(client)
    full_entry(client)
    files = stored_files(app)
    assert len(files) == 3
    for path in files:
        blob = open(path, "rb").read()
        assert blob.startswith(b"DUDU1")
        assert PHOTO not in blob and VIDEO[:40] not in blob and b"bruise" not in blob
    assert scan_media_files(app.config["MEDIA_DIR"])[0].level == "PASS"
    # Original file names and fingerprints are encrypted in the database too.
    assert b"bruise.png" not in open(app.config["DATABASE"], "rb").read()


@pos
def test_video_supports_byte_ranges_for_iphone(client):
    register(client)
    full_entry(client)
    r = client.get("/journal/media/2", headers={"Range": "bytes=0-9"})
    assert r.status_code == 206 and r.data == VIDEO[:10]
    assert r.headers["Content-Range"] == f"bytes 0-9/{len(VIDEO)}"


@pos
def test_media_response_is_sandboxed(client):
    register(client)
    full_entry(client)
    h = client.get("/journal/media/1").headers
    assert "sandbox" in h["Content-Security-Policy"] and h["X-Content-Type-Options"] == "nosniff"
    assert "no-store" in h["Cache-Control"]


@pos
def test_workplace_incident_recorded(client):
    register(client)
    r = add_journal(client, setting="workplace", type="sexual harassment", employer="Acme Retail",
                    perpetrator_role="manager or supervisor", reported="yes, to HR", report_ref="HR-2291",
                    work_impact="Moved to night shift after I complained")
    assert r.status_code == 302
    html = client.get("/journal").get_data(as_text=True)
    for text in ("Acme Retail", "manager or supervisor", "yes, to HR", "HR-2291", "night shift", "workplace"):
        assert text in html


@pos
def test_workplace_fields_not_kept_for_home_incidents(client):
    register(client)
    add_journal(client, setting="home", employer="Should Not Appear Ltd")
    assert "Should Not Appear Ltd" not in client.get("/journal").get_data(as_text=True)


@pos
def test_pdf_report(client):
    register(client)
    full_entry(client)
    add_journal(client, setting="workplace", employer="Acme", description="“Curly quotes”, ê, emoji 😢")
    r = client.get("/my-data/report.pdf")
    assert r.status_code == 200 and r.mimetype == "application/pdf"
    assert r.data.startswith(b"%PDF") and "attachment" in r.headers["Content-Disposition"]


@pos
def test_evidence_pack_zip_has_originals_and_fingerprints(client):
    register(client)
    full_entry(client)
    r = client.get("/my-data/evidence.zip")
    assert r.status_code == 200 and r.mimetype == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.data))
    names = z.namelist()
    assert "incident-record.pdf" in names and "fingerprints.txt" in names and "incidents.json" in names
    photo_path = next(n for n in names if n.endswith("bruise.png"))
    assert z.read(photo_path) == PHOTO
    assert f"{hashlib.sha256(PHOTO).hexdigest()}  {photo_path}" in z.read("fingerprints.txt").decode()


@pos
def test_printable_page(client):
    register(client)
    full_entry(client)
    html = client.get("/my-data/print").get_data(as_text=True)
    assert "Incident record" in html and "He threw my phone at the wall" in html
    assert hashlib.sha256(PHOTO).hexdigest() in html and 'id="print-btn"' in html


@pos
def test_safety_plan_kept_out_of_court_exports(client):
    register(client)
    full_entry(client)
    client.post("/safety-plan", data={"_csrf": csrf(client, "/safety-plan"), "safe_place": "Auntie Zodwa in Umlazi"})
    assert "Zodwa" not in client.get("/my-data/print").get_data(as_text=True)
    z = zipfile.ZipFile(io.BytesIO(client.get("/my-data/evidence.zip").data))
    assert all(b"Zodwa" not in z.read(n) for n in z.namelist())
    assert "Zodwa" in client.get("/my-data/export").get_data(as_text=True)  # JSON = everything, by design


@pos
def test_deleting_entry_file_or_account_removes_files_from_disk(app, client):
    register(client)
    full_entry(client)
    full_entry(client)
    assert len(stored_files(app)) == 6
    client.post("/journal/media/1/delete", data={"_csrf": csrf(client, "/journal")})
    assert len(stored_files(app)) == 5
    client.post("/journal/1/delete", data={"_csrf": csrf(client, "/journal")})
    assert len(stored_files(app)) == 3
    client.post("/my-data/delete", data={"_csrf": csrf(client, "/my-data"), "password": PASSWORD})
    assert stored_files(app) == []


@pos
def test_purge_removes_orphaned_files(app, client):
    register(client)
    full_entry(client)
    open(os.path.join(app.config["MEDIA_DIR"], "0" * 32 + ".bin"), "wb").write(b"DUDU1orphan")
    with app.app_context():
        from app.db import purge_expired
        assert purge_expired(30, 365)["orphan_files"] == 1
    assert len(stored_files(app)) == 3


@pos
def test_chatbot_helps_with_workplace_harassment(client):
    body = chat(client, "my manager keeps sending me sexual messages at work").get_json()
    assert body["intent"] == "workplace" and "CCMA" in body["text"]
    assert any(h["name"] == "CCMA" for h in body["resources"])


@pos
def test_installable_app_files(client):
    m = client.get("/manifest.webmanifest")
    data = json.loads(m.data)
    assert m.mimetype == "application/manifest+json" and data["name"] == "Dudu"
    assert {i["sizes"] for i in data["icons"]} >= {"192x192", "512x512"}
    for icon in data["icons"]:
        assert client.get(icon["src"]).status_code == 200
    sw = client.get("/sw.js")
    assert sw.status_code == 200 and "javascript" in sw.headers["Content-Type"]
    offline = client.get("/offline").get_data(as_text=True)
    assert "10111" in offline and "0800 428 428" in offline
    assert 'rel="manifest"' in client.get("/").get_data(as_text=True)


@pos
def test_service_worker_never_caches_private_pages():
    sw = open(os.path.join(os.path.dirname(__file__), "..", "app", "static", "sw.js"), encoding="utf-8").read()
    shell = sw[sw.index("const SHELL"):sw.index("];")]
    for private in ("/journal", "/my-data", "/safety-plan", "/api/", "/counsellor", "/callback"):
        assert private not in shell


# ================================================================= negative
@neg
@pytest.mark.parametrize("data, name, mime", [
    (b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>", "pic.svg", "image/svg+xml"),
    (b"<html><script>alert(1)</script></html>", "photo.jpg", "image/jpeg"),
    (b"MZ\x90\x00" + bytes(100), "holiday.jpg", "image/jpeg"),
    (b"%PDF-1.7 fake", "scan.png", "image/png"),
    (b"PK\x03\x04" + bytes(50), "voice.m4a", "audio/mp4"),
])
def test_disguised_or_dangerous_files_rejected(app, client, data, name, mime):
    register(client)
    r = add_journal(client, **attach((data, name, mime)))
    assert r.status_code == 400 and "supported file" in r.get_data(as_text=True)
    assert rows(app, "SELECT COUNT(*) FROM journal_entries")[0][0] == 0
    assert stored_files(app) == []


@neg
def test_empty_file_rejected(client):
    register(client)
    assert add_journal(client, **attach((b"", "empty.png", "image/png"))).status_code == 400


@neg
def test_oversized_file_rejected(make_app):
    app = make_app(MEDIA_LIMITS={"image": 100, "audio": 100, "video": 100})
    c = app.test_client()
    register(c)
    r = add_journal(c, **attach((PHOTO, "big.png", "image/png")))
    assert r.status_code == 400 and "too big" in r.get_data(as_text=True)


@neg
def test_too_many_files_rejected(client):
    register(client)
    r = add_journal(client, **attach(*[(PHOTO, f"p{i}.png", "image/png") for i in range(6)]))
    assert r.status_code == 400 and "up to 5 files" in r.get_data(as_text=True)


@neg
def test_storage_quota_enforced(make_app):
    app = make_app(MEDIA_USER_QUOTA=len(PHOTO) + 10)
    c = app.test_client()
    register(c)
    assert add_journal(c, **attach((PHOTO, "a.png", "image/png"))).status_code == 302
    r = add_journal(c, **attach((PHOTO, "b.png", "image/png")))
    assert r.status_code == 400 and "storage is full" in r.get_data(as_text=True)


@neg
def test_request_over_total_upload_limit_rejected(make_app):
    app = make_app(MAX_UPLOAD_BYTES=2000)
    c = app.test_client()
    register(c)
    assert add_journal(c, **attach((bytes(5000), "x.png", "image/png"))).status_code == 413


@neg
def test_other_routes_keep_small_body_limit(client):
    r = client.post("/callback", data={"_csrf": csrf(client, "/callback"), "notes": "x" * 70_000})
    assert r.status_code == 413


@neg
def test_other_users_cannot_view_or_delete_my_files(app):
    a, b = app.test_client(), app.test_client()
    register(a, "alice1")
    full_entry(a)
    register(b, "bongi1")
    assert b.get("/journal/media/1").status_code == 404
    assert b.post("/journal/media/1/delete", data={"_csrf": csrf(b, "/journal")}).status_code == 404
    assert a.get("/journal/media/1").status_code == 200


@neg
@pytest.mark.parametrize("path", ["/journal/media/1", "/my-data/report.pdf", "/my-data/evidence.zip",
                                  "/my-data/print"])
def test_logged_out_users_cannot_reach_evidence_or_exports(client, path):
    r = client.get(path)
    assert r.status_code == 302 and "/login" in r.headers["Location"]


@neg
def test_tampered_file_is_refused_not_served(app, client):
    register(client)
    full_entry(client)
    path = os.path.join(app.config["MEDIA_DIR"], rows(app, "SELECT stored_name FROM journal_media WHERE id=1")[0][0])
    blob = bytearray(open(path, "rb").read())
    blob[-1] ^= 0xFF
    open(path, "wb").write(bytes(blob))
    assert client.get("/journal/media/1").status_code == 404
    assert client.get("/journal").status_code == 200
    assert client.get("/my-data/report.pdf").status_code == 200  # the report still builds


@neg
def test_file_swapped_between_users_cannot_be_decrypted(app):
    a, b = app.test_client(), app.test_client()
    register(a, "alice1")
    full_entry(a)
    register(b, "bongi1")
    full_entry(b)
    names = dict(rows(app, "SELECT id, stored_name FROM journal_media"))
    d = app.config["MEDIA_DIR"]
    shutil.copy(os.path.join(d, names[1]), os.path.join(d, names[4]))  # alice's photo over bongi's
    assert b.get("/journal/media/4").status_code == 404


@neg
@pytest.mark.parametrize("name", ["../../etc/passwd", "..\\db.sqlite", "abc.bin", "x" * 32 + ".bin"])
def test_stored_name_cannot_escape_media_folder(app, name):
    from app.crypto import DecryptionError
    from app.media import read_decrypted
    with app.app_context(), pytest.raises((DecryptionError, FileNotFoundError)):
        read_decrypted(app.extensions["vault"], 1, name)


@neg
@pytest.mark.parametrize("field, value", [("setting", "the moon"), ("perpetrator_role", "alien"),
                                          ("reported", "maybe"), ("type", "unknown harm")])
def test_invalid_journal_choices_rejected(client, field, value):
    register(client)
    data = {"setting": "workplace", field: value}
    assert add_journal(client, **data).status_code == 400


@neg
def test_scanner_detects_unencrypted_media(app, client):
    register(client)
    full_entry(client)
    open(os.path.join(app.config["MEDIA_DIR"], "f" * 32 + ".bin"), "wb").write(PHOTO)
    assert scan_media_files(app.config["MEDIA_DIR"])[0].level == "FAIL"
