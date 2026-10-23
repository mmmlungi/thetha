"""Web security controls: CSRF, rate limiting, headers, validation, auth, log redaction."""
import hmac
import logging
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import date
from functools import wraps

from flask import abort, current_app, g, jsonify, redirect, request, session, url_for

CSRF_EXEMPT = {"main.quick_exit", "static"}  # quick-exit only *clears* the session

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SA_PHONE = re.compile(r"^(?:\+27|0)\d{9}$")
COMMON_PASSWORDS = {"password", "password1", "12345678", "123456789", "qwerty123", "iloveyou",
                    "11111111", "abc12345", "password123", "letmein1"}

PHONE_IN_TEXT = re.compile(r"(?:\+27|\b0)\d{2}[\s-]?\d{3}[\s-]?\d{4}\b")
EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


class ValidationError(ValueError):
    pass


# ---------------------------------------------------------------- validation
def clean_text(value, max_len: int, required: bool = False, field: str = "field") -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text")
    value = CONTROL_CHARS.sub("", value).strip()
    if required and not value:
        raise ValidationError(f"{field} is required")
    if len(value) > max_len:
        raise ValidationError(f"{field} is too long (max {max_len} characters)")
    return value


def clean_choice(value, choices, field: str = "field", required: bool = True):
    if not value and not required:
        return None
    if value not in choices:
        raise ValidationError(f"{field} is not a valid option")
    return value


def clean_phone(value) -> str:
    value = re.sub(r"[\s-]", "", clean_text(value, 20, required=True, field="Phone number"))
    if not SA_PHONE.match(value):
        raise ValidationError("Phone number must be a South African number, e.g. 0821234567")
    return value


def clean_past_date(value, field: str = "Date") -> str:
    try:
        d = date.fromisoformat(clean_text(value, 10, required=True, field=field))
    except ValueError as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError(f"{field} must be a valid date") from exc
    if d > date.today():
        raise ValidationError(f"{field} cannot be in the future")
    return d.isoformat()


def check_password_policy(password: str):
    if not isinstance(password, str) or len(password) < 8:
        raise ValidationError("Password must be at least 8 characters")
    if len(password) > 128:
        raise ValidationError("Password is too long")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValidationError("Password must contain letters and numbers")
    if password.lower() in COMMON_PASSWORDS:
        raise ValidationError("That password is too common")


def clean_username(value) -> str:
    value = clean_text(value, 32, required=True, field="Username")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", value):
        raise ValidationError("Username: 3-32 letters, numbers, dot, dash or underscore")
    return value


# ---------------------------------------------------------------- CSRF
def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def verify_csrf():
    if request.method != "POST" or request.endpoint in CSRF_EXEMPT:
        return
    sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, description="Your session expired. Please reload the page and try again.")


# ---------------------------------------------------------------- rate limiting
class RateLimiter:
    """In-memory sliding window. Swap for Redis when running more than one worker."""

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def rate_limit(bucket: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            limit, window = current_app.config["RATE_LIMITS"][bucket]
            if request.method == "POST" and not limiter.allow(f"{bucket}:{request.remote_addr}", limit, window):
                abort(429)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------- auth
def login_required(role: str | None = None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.get("user") is None:
                if request.path.startswith("/api/"):
                    return jsonify(error="Login required"), 401
                return redirect(url_for("main.login", next=request.path))
            if role and g.user["role"] != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------- headers
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'")


def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    # Shared phones: never let the browser cache pages a partner could reopen with "back".
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    if current_app.config.get("ENV_NAME") == "production":
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# ---------------------------------------------------------------- logs
def redact(text: str) -> str:
    return EMAIL_IN_TEXT.sub("[email]", PHONE_IN_TEXT.sub("[phone]", text))


class RedactPIIFilter(logging.Filter):
    """Defence in depth: even if someone logs user input by mistake, PII is masked."""

    def filter(self, record):
        record.msg = redact(record.getMessage())
        record.args = None
        return True


def init_app(app):
    app.before_request(verify_csrf)
    app.after_request(set_security_headers)
    app.jinja_env.globals["csrf_token"] = csrf_token
    pii_filter = RedactPIIFilter()
    for name in (app.logger.name, "werkzeug"):
        logging.getLogger(name).addFilter(pii_filter)
