import hashlib
import json
import secrets
from collections import Counter
from datetime import date, datetime, timedelta, timezone

import click
from flask.cli import with_appcontext
from flask import (Blueprint, Response, abort, current_app, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from . import chatbot, exports, media
from .crypto import DecryptionError
from .db import audit, get_db, utcnow
from .resources import (HELPLINES, JOURNAL_SETTINGS, JOURNAL_TYPES, PROTECTION_ORDER_STEPS, PROVINCES,
                        SAFETY_PLAN_DOCUMENTS, WORKPLACE_REPORTED, WORKPLACE_ROLES)
from .security import (ValidationError, check_password_policy, clean_choice, clean_past_date,
                       clean_phone, clean_text, clean_username, login_required, rate_limit)

bp = Blueprint("main", __name__)

# A real hash of a random value, so unknown usernames take as long as wrong passwords.
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(16))


def vault():
    return current_app.extensions["vault"]


@bp.before_app_request
def load_user():
    session.permanent = True
    g.user = None
    uid = session.get("uid")
    if uid is not None:
        g.user = get_db().execute("SELECT id, role, alias_enc, username_index FROM users WHERE id = ?",
                                  (uid,)).fetchone()
        if g.user is None:
            session.clear()


@bp.app_template_filter("filesize")
def filesize(n):
    return exports.human_size(int(n or 0)) if n else "0 KB"


@bp.app_context_processor
def inject_alias():
    alias = None
    if g.get("user") is not None:
        try:
            alias = vault().decrypt(g.user["alias_enc"], f"alias:{g.user['username_index']}")
        except DecryptionError:
            alias = "you"
    return {"current_alias": alias}


@bp.app_errorhandler(400)
@bp.app_errorhandler(403)
@bp.app_errorhandler(404)
@bp.app_errorhandler(413)
@bp.app_errorhandler(429)
def handle_error(err):
    messages = {429: "Too many requests. Please wait a moment and try again.",
                413: "That message is too large."}
    msg = messages.get(err.code) or getattr(err, "description", "Something went wrong")
    if request.path.startswith("/api/"):
        return jsonify(error=msg), err.code
    return render_template("error.html", code=err.code, message=msg), err.code


# ---------------------------------------------------------------- chat
@bp.get("/")
def index():
    return render_template("chat.html", provinces=PROVINCES)


@bp.post("/api/chat")
@rate_limit("chat")
def api_chat():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Expected a JSON body"), 400
    try:
        message = clean_text(data.get("message"), 500, required=True, field="Message")
        province = clean_choice(data.get("province") or None, PROVINCES, "Province", required=False)
    except ValidationError as exc:
        return jsonify(error=str(exc)), 400

    reply = chatbot.respond(chatbot.expand_quick_reply(message), session.get("chat_state"))
    session["chat_state"] = reply.state
    # Only an anonymous statistic is kept, never the message itself.
    db = get_db()
    db.execute("INSERT INTO chat_events (day, intent, risk_level, language, province) VALUES (?, ?, ?, ?, ?)",
               (date.today().isoformat(), reply.intent, reply.risk_level, reply.language, province))
    db.commit()
    return jsonify(reply.to_dict())


@bp.post("/quick-exit")
def quick_exit():
    session.clear()
    return ("", 204)


@bp.get("/resources")
def resources():
    return render_template("resources.html", helplines=HELPLINES.values(), steps=PROTECTION_ORDER_STEPS)


@bp.get("/healthz")
def healthz():
    return jsonify(status="ok")


# ---------------------------------------------------------------- installable app (PWA)
@bp.get("/manifest.webmanifest")
def manifest():
    icon = lambda f, size, purpose: {"src": url_for("static", filename=f), "sizes": size,  # noqa: E731
                                     "type": "image/png", "purpose": purpose}
    data = {
        "name": "Dudu", "short_name": "Dudu",
        "description": "Private support, safety planning and an encrypted journal.",
        "start_url": "/", "scope": "/", "display": "standalone", "orientation": "portrait",
        "background_color": "#ff4d00", "theme_color": "#ff4d00",
        "icons": [icon("icon-192.png", "192x192", "any"), icon("icon-512.png", "512x512", "any"),
                  icon("icon-maskable-512.png", "512x512", "maskable")],
    }
    return Response(json.dumps(data), mimetype="application/manifest+json")


@bp.get("/sw.js")
def service_worker():
    # Served from the site root so it may control every page.
    resp = current_app.send_static_file("sw.js")
    resp.headers["Content-Type"] = "application/javascript"
    return resp


@bp.get("/offline")
def offline():
    return render_template("offline.html")


# ---------------------------------------------------------------- accounts
@bp.route("/register", methods=["GET", "POST"])
@rate_limit("register")
def register():
    if request.method == "POST":
        try:
            username = clean_username(request.form.get("username"))
            password = request.form.get("password", "")
            check_password_policy(password)
            if password != request.form.get("confirm", ""):
                raise ValidationError("Passwords do not match")
        except ValidationError as exc:
            flash(str(exc), "error")
            return render_template("register.html"), 400
        index = vault().blind_index(username)
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username_index = ?", (index,)).fetchone():
            flash("That username is taken. Please choose another.", "error")
            return render_template("register.html"), 400
        cur = db.execute(
            "INSERT INTO users (username_index, alias_enc, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (index, vault().encrypt(username, f"alias:{index}"), generate_password_hash(password),
             "survivor", utcnow()))
        db.commit()
        session.clear()
        session["uid"] = cur.lastrowid
        flash("Account created. Your journal and safety plan are encrypted.", "ok")
        return redirect(url_for("main.journal"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
@rate_limit("login")
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        user = None
        if isinstance(username, str) and 0 < len(username) <= 64:
            user = db.execute("SELECT * FROM users WHERE username_index = ?",
                              (vault().blind_index(username),)).fetchone()
        now = datetime.now(timezone.utc)
        if user and user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > now:
            flash("Too many failed attempts. Try again later.", "error")
            return render_template("login.html"), 429
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if not (user and ok):
            if user:
                fails = user["failed_logins"] + 1
                locked = None
                if fails >= current_app.config["LOCKOUT_THRESHOLD"]:
                    locked = (now + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])).isoformat()
                    fails = 0
                    audit("account_locked", user["role"], f"user:{user['id']}")
                db.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                           (fails, locked, user["id"]))
                db.commit()
            flash("Incorrect username or password.", "error")  # same message: no user enumeration
            return render_template("login.html"), 401
        db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        db.commit()
        session.clear()                       # prevent session fixation
        session["uid"] = user["id"]
        if user["role"] == "counsellor":
            audit("counsellor_login", "counsellor", f"user:{user['id']}")
            return redirect(url_for("main.counsellor"))
        nxt = request.args.get("next", "")
        # Only allow local redirects (open-redirect protection).
        if not (nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt):
            nxt = url_for("main.journal")
        return redirect(nxt)
    return render_template("login.html")


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.index"))


# ---------------------------------------------------------------- journal (encrypted, with evidence files)
def _journal_ctx(uid):
    return f"journal:{uid}"


def _storage_used(uid):
    return get_db().execute("SELECT COALESCE(SUM(size), 0) FROM journal_media WHERE user_id = ?",
                            (uid,)).fetchone()[0]


def _journal_page(uid, status=200):
    cfg = current_app.config
    return render_template("journal.html", entries=_load_journal(uid), types=JOURNAL_TYPES,
                           settings=JOURNAL_SETTINGS, roles=WORKPLACE_ROLES, reported=WORKPLACE_REPORTED,
                           storage=_storage_used(uid), quota=cfg["MEDIA_USER_QUOTA"],
                           max_files=cfg["MEDIA_MAX_FILES_PER_ENTRY"], form=request.form), status


def _read_entry_form():
    setting = clean_choice(request.form.get("setting") or "home", JOURNAL_SETTINGS, "Where it happened")
    entry = {
        "date": clean_past_date(request.form.get("date"), "Incident date"),
        "type": clean_choice(request.form.get("type"), JOURNAL_TYPES, "Type of abuse"),
        "setting": setting,
        "description": clean_text(request.form.get("description"), 4000, True, "What happened"),
        "location": clean_text(request.form.get("location"), 200, field="Location"),
        "injuries": clean_text(request.form.get("injuries"), 1000, field="Injuries"),
        "witnesses": clean_text(request.form.get("witnesses"), 500, field="Witnesses"),
    }
    if setting == "workplace":
        entry.update({
            "employer": clean_text(request.form.get("employer"), 120, field="Employer"),
            "perpetrator_role": clean_choice(request.form.get("perpetrator_role") or None, WORKPLACE_ROLES,
                                             "Their role at work", required=False) or "",
            "reported": clean_choice(request.form.get("reported") or "not yet", WORKPLACE_REPORTED,
                                     "Have you reported it"),
            "report_ref": clean_text(request.form.get("report_ref"), 80, field="Reference number"),
            "work_impact": clean_text(request.form.get("work_impact"), 1000, field="Impact on your work"),
        })
    return entry


@bp.route("/journal", methods=["GET", "POST"])
@login_required()
@rate_limit("write")
def journal():
    db, uid, v = get_db(), g.user["id"], vault()
    if request.method == "POST":
        try:
            entry = _read_entry_form()
            uploads = media.read_uploads(request.files.getlist("media"), _storage_used(uid))
        except ValidationError as exc:
            flash(str(exc), "error")
            return _journal_page(uid, 400)
        written = []
        try:
            cur = db.execute("INSERT INTO journal_entries (user_id, payload_enc, created_at) VALUES (?, ?, ?)",
                             (uid, v.encrypt_json(entry, _journal_ctx(uid)), utcnow()))
            for item in uploads:
                name = media.write_encrypted(v, uid, item["data"])
                written.append(name)
                meta = {"name": item["name"], "mime": item["mime"], "kind": item["kind"],
                        "size": len(item["data"]), "sha256": hashlib.sha256(item["data"]).hexdigest()}
                db.execute("INSERT INTO journal_media (entry_id, user_id, stored_name, size, meta_enc, created_at) "
                           "VALUES (?, ?, ?, ?, ?, ?)",
                           (cur.lastrowid, uid, name, meta["size"], v.encrypt_json(meta, media.meta_ctx(uid, name)),
                            utcnow()))
            db.commit()
        except Exception:
            db.rollback()
            media.delete_files(written)  # never leave orphaned evidence behind
            raise
        n = len(uploads)
        flash("Entry saved and encrypted." + (f" {n} file{'s' if n != 1 else ''} attached." if n else ""), "ok")
        return redirect(url_for("main.journal"))
    return _journal_page(uid)


def _load_media(uid):
    by_entry = {}
    rows = get_db().execute("SELECT id, entry_id, stored_name, size, meta_enc, created_at FROM journal_media "
                            "WHERE user_id = ? ORDER BY id", (uid,)).fetchall()
    for r in rows:
        try:
            meta = vault().decrypt_json(r["meta_enc"], media.meta_ctx(uid, r["stored_name"]))
        except DecryptionError:
            meta = {"name": "[unreadable file]", "mime": "application/octet-stream", "kind": "image",
                    "sha256": "-", "size": r["size"], "broken": True}
        by_entry.setdefault(r["entry_id"], []).append(
            {"id": r["id"], "stored_name": r["stored_name"], "uploaded_at": r["created_at"], **meta})
    return by_entry


def _load_journal(uid, oldest_first=False):
    order = "ASC" if oldest_first else "DESC"
    rows = get_db().execute("SELECT id, payload_enc, created_at FROM journal_entries WHERE user_id = ? "
                            f"ORDER BY id {order}", (uid,)).fetchall()  # nosec B608 - order is a constant
    files = _load_media(uid)
    entries = []
    for r in rows:
        try:
            data = vault().decrypt_json(r["payload_enc"], _journal_ctx(uid))
        except DecryptionError:
            current_app.logger.error("Journal entry %s failed integrity check", r["id"])
            data = {"date": "-", "type": "other", "description": "[This entry could not be decrypted]"}
        entries.append({"id": r["id"], "created_at": r["created_at"], "media": files.get(r["id"], []), **data})
    # Order by when it happened, not when it was typed in (people often write things down later).
    entries.sort(key=lambda e: (e.get("date") or "", e["id"]), reverse=not oldest_first)
    return entries


@bp.get("/journal/media/<int:media_id>")
@login_required()
def journal_media(media_id):
    uid = g.user["id"]
    # user_id in the WHERE clause: nobody can open someone else's file by guessing its number (IDOR).
    row = get_db().execute("SELECT stored_name, meta_enc FROM journal_media WHERE id = ? AND user_id = ?",
                           (media_id, uid)).fetchone()
    if row is None:
        abort(404)
    try:
        meta = vault().decrypt_json(row["meta_enc"], media.meta_ctx(uid, row["stored_name"]))
        data = media.read_decrypted(vault(), uid, row["stored_name"])
    except (DecryptionError, OSError):
        current_app.logger.error("Evidence file %s failed integrity check", media_id)
        abort(404)
    rng = request.range
    span = rng.range_for_length(len(data)) if rng else None
    if span:  # iPhones need byte ranges to play video and audio
        resp = Response(data[span[0]:span[1]], 206, mimetype=meta["mime"])
        resp.headers["Content-Range"] = rng.to_content_range_header(len(data))
    else:
        resp = Response(data, mimetype=meta["mime"])
    resp.headers["Accept-Ranges"] = "bytes"
    disposition = "attachment" if request.args.get("download") else "inline"
    resp.headers["Content-Disposition"] = f'{disposition}; filename="{meta["name"]}"'
    resp.headers["Content-Security-Policy"] = "default-src 'none'; img-src 'self'; media-src 'self'; sandbox"
    return resp


@bp.post("/journal/media/<int:media_id>/delete")
@login_required()
def journal_media_delete(media_id):
    db = get_db()
    row = db.execute("SELECT stored_name FROM journal_media WHERE id = ? AND user_id = ?",
                     (media_id, g.user["id"])).fetchone()
    if row is None:
        abort(404)
    db.execute("DELETE FROM journal_media WHERE id = ?", (media_id,))
    db.commit()
    media.delete_files([row["stored_name"]])
    flash("File permanently deleted.", "ok")
    return redirect(url_for("main.journal"))


@bp.post("/journal/<int:entry_id>/delete")
@login_required()
def journal_delete(entry_id):
    db = get_db()
    names = [r[0] for r in db.execute("SELECT stored_name FROM journal_media WHERE entry_id = ? AND user_id = ?",
                                      (entry_id, g.user["id"]))]
    # user_id in the WHERE clause prevents deleting someone else's entry (IDOR).
    cur = db.execute("DELETE FROM journal_entries WHERE id = ? AND user_id = ?", (entry_id, g.user["id"]))
    db.commit()
    if cur.rowcount == 0:
        abort(404)
    media.delete_files(names)
    flash("Entry permanently deleted.", "ok")
    return redirect(url_for("main.journal"))


# ---------------------------------------------------------------- safety plan (encrypted)
@bp.route("/safety-plan", methods=["GET", "POST"])
@login_required()
@rate_limit("write")
def safety_plan():
    db, uid = get_db(), g.user["id"]
    ctx = f"safety:{uid}"
    if request.method == "POST":
        try:
            plan = {
                "contacts": clean_text(request.form.get("contacts"), 500, field="Trusted contacts"),
                "code_word": clean_text(request.form.get("code_word"), 50, field="Code word"),
                "safe_place": clean_text(request.form.get("safe_place"), 300, field="Safe place"),
                "bag_location": clean_text(request.form.get("bag_location"), 200, field="Emergency bag"),
                "documents": [d for d in request.form.getlist("documents") if d in SAFETY_PLAN_DOCUMENTS],
                "notes": clean_text(request.form.get("notes"), 2000, field="Notes"),
            }
        except ValidationError as exc:
            flash(str(exc), "error")
            return render_template("safety_plan.html", plan=request.form, docs=SAFETY_PLAN_DOCUMENTS), 400
        db.execute("INSERT INTO safety_plans (user_id, payload_enc, updated_at) VALUES (?, ?, ?) "
                   "ON CONFLICT(user_id) DO UPDATE SET payload_enc = excluded.payload_enc, "
                   "updated_at = excluded.updated_at",
                   (uid, vault().encrypt_json(plan, ctx), utcnow()))
        db.commit()
        flash("Safety plan saved and encrypted.", "ok")
        return redirect(url_for("main.safety_plan"))
    row = db.execute("SELECT payload_enc FROM safety_plans WHERE user_id = ?", (uid,)).fetchone()
    plan = vault().decrypt_json(row["payload_enc"], ctx) if row else {}
    return render_template("safety_plan.html", plan=plan, docs=SAFETY_PLAN_DOCUMENTS)


# ---------------------------------------------------------------- POPIA: access, export & erasure
def _alias():
    try:
        return vault().decrypt(g.user["alias_enc"], f"alias:{g.user['username_index']}")
    except DecryptionError:
        return "Dudu user"


def _download(data, mimetype, stem, ext):
    return Response(data, mimetype=mimetype, headers={
        "Content-Disposition": f"attachment; filename={stem}-{date.today().isoformat()}.{ext}"})


def _my_data_page(status=200):
    uid = g.user["id"]
    count = get_db().execute("SELECT COUNT(*) FROM journal_entries WHERE user_id = ?", (uid,)).fetchone()[0]
    return render_template("my_data.html", entry_count=count, storage=_storage_used(uid),
                           quota=current_app.config["MEDIA_USER_QUOTA"]), status


@bp.get("/my-data")
@login_required()
def my_data():
    return _my_data_page()


@bp.get("/my-data/report.pdf")
@login_required()
def my_data_pdf():
    uid = g.user["id"]
    pdf = exports.build_pdf(_load_journal(uid, oldest_first=True), _alias(), vault(), uid)
    audit("export_pdf", "survivor", f"user:{uid}")
    return _download(pdf, "application/pdf", "incident-record", "pdf")


@bp.get("/my-data/evidence.zip")
@login_required()
def my_data_zip():
    uid = g.user["id"]
    entries = _load_journal(uid, oldest_first=True)
    pdf = exports.build_pdf(entries, _alias(), vault(), uid)
    audit("export_zip", "survivor", f"user:{uid}")
    return _download(exports.build_zip(entries, _alias(), vault(), uid, pdf), "application/zip",
                     "evidence-pack", "zip")


@bp.get("/my-data/print")
@login_required()
def my_data_print():
    uid = g.user["id"]
    audit("export_print", "survivor", f"user:{uid}")
    return render_template("journal_print.html", entries=_load_journal(uid, oldest_first=True), alias=_alias(),
                           generated=datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC"))


@bp.get("/my-data/export")
@login_required()
def my_data_export():
    uid = g.user["id"]
    row = get_db().execute("SELECT payload_enc FROM safety_plans WHERE user_id = ?", (uid,)).fetchone()
    journal_items = []
    for e in _load_journal(uid, oldest_first=True):
        e["media"] = [{k: m[k] for k in ("name", "mime", "kind", "size", "sha256", "uploaded_at") if k in m}
                      for m in e["media"]]
        journal_items.append(e)
    export = {
        "exported_at": utcnow(),
        "journal": journal_items,
        "safety_plan": vault().decrypt_json(row["payload_enc"], f"safety:{uid}") if row else None,
    }
    audit("data_export", "survivor", f"user:{uid}")
    return _download(json.dumps(export, indent=2), "application/json", "my-records", "json")


@bp.post("/my-data/delete")
@login_required()
def my_data_delete():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    if not check_password_hash(user["password_hash"], request.form.get("password", "")):
        flash("Password incorrect. Nothing was deleted.", "error")
        return _my_data_page(401)
    names = [r[0] for r in db.execute("SELECT stored_name FROM journal_media WHERE user_id = ?", (user["id"],))]
    db.execute("DELETE FROM users WHERE id = ?", (user["id"],))  # cascades to journal, files table, plan
    db.commit()
    db.execute("VACUUM")                                         # rewrite file, drop freed pages
    media.delete_files(names)
    audit("account_erased", "survivor", None)
    session.clear()
    flash("All your data has been permanently deleted.", "ok")
    return redirect(url_for("main.index"))


# ---------------------------------------------------------------- callbacks (encrypted PII)
@bp.route("/callback", methods=["GET", "POST"])
@rate_limit("callback")
def callback():
    if request.method == "POST":
        try:
            payload = {
                "name": clean_text(request.form.get("name"), 60, field="Name"),
                "phone": clean_phone(request.form.get("phone")),
                "safe_time": clean_text(request.form.get("safe_time"), 100, True, "Safe time to call"),
                "leave_message": request.form.get("leave_message") == "yes",
                "notes": clean_text(request.form.get("notes"), 1000, field="Notes"),
            }
            province = clean_choice(request.form.get("province"), PROVINCES, "Province")
            urgency = clean_choice(request.form.get("urgency"), ("normal", "urgent"), "Urgency")
        except ValidationError as exc:
            flash(str(exc), "error")
            return render_template("callback.html", provinces=PROVINCES), 400
        ref = secrets.token_hex(4).upper()
        db = get_db()
        db.execute("INSERT INTO callback_requests (ref, payload_enc, province, urgency, created_at) "
                   "VALUES (?, ?, ?, ?, ?)",
                   (ref, vault().encrypt_json(payload, f"callback:{ref}"), province, urgency, utcnow()))
        db.commit()
        return render_template("callback_done.html", ref=ref)
    return render_template("callback.html", provinces=PROVINCES)


# ---------------------------------------------------------------- counsellor dashboard
@bp.get("/counsellor")
@login_required(role="counsellor")
def counsellor():
    db = get_db()
    since = (date.today() - timedelta(days=30)).isoformat()
    events = db.execute("SELECT intent, risk_level, language, province FROM chat_events WHERE day >= ?",
                        (since,)).fetchall()
    stats = {
        "total": len(events),
        "intents": Counter(e["intent"] for e in events).most_common(8),
        "risk": Counter(e["risk_level"] for e in events if e["risk_level"]),
        "languages": Counter(e["language"] for e in events).most_common(),
        "provinces": Counter(e["province"] for e in events if e["province"]).most_common(),
    }
    callbacks = []
    for r in db.execute("SELECT * FROM callback_requests WHERE status = 'open' "
                        "ORDER BY urgency = 'urgent' DESC, id").fetchall():
        try:
            data = vault().decrypt_json(r["payload_enc"], f"callback:{r['ref']}")
        except DecryptionError:
            data = {"name": "[integrity check failed]", "phone": "-", "safe_time": "-"}
        callbacks.append({**dict(r), **data})
    audit("view_callbacks", "counsellor", f"count:{len(callbacks)}")
    return render_template("counsellor.html", stats=stats, callbacks=callbacks)


@bp.post("/counsellor/callback/<int:cb_id>/close")
@login_required(role="counsellor")
def counsellor_close(cb_id):
    db = get_db()
    cur = db.execute("UPDATE callback_requests SET status = 'closed', closed_at = ? WHERE id = ? AND status = 'open'",
                     (utcnow(), cb_id))
    db.commit()
    if cur.rowcount == 0:
        abort(404)
    audit("close_callback", "counsellor", f"callback:{cb_id}")
    return redirect(url_for("main.counsellor"))


@click.command("create-counsellor")
@click.argument("username")
@click.password_option()
@with_appcontext
def create_counsellor_command(username, password):
    """Create a counsellor account (staff only)."""
    username = clean_username(username)
    check_password_policy(password)
    v = vault()
    index = v.blind_index(username)
    db = get_db()
    db.execute("INSERT INTO users (username_index, alias_enc, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
               (index, v.encrypt(username, f"alias:{index}"), generate_password_hash(password),
                "counsellor", utcnow()))
    db.commit()
    click.echo("Counsellor created.")
