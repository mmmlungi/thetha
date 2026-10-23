"""Thetha - a safe, private GBV support chatbot for South Africa."""
import json
import os
import secrets
from datetime import timedelta

from flask import Flask

from . import db, security
from .crypto import Vault, generate_master_key


def _load_keys(app):
    """Keys come from the environment. Production refuses to start without them."""
    secret = os.environ.get("THETHA_SECRET_KEY") or app.config.get("SECRET_KEY")
    master = os.environ.get("THETHA_MASTER_KEY") or app.config.get("MASTER_KEY")
    if secret and master:
        app.config.update(SECRET_KEY=secret, MASTER_KEY=master)
        return
    if app.config["ENV_NAME"] == "production":
        raise RuntimeError("THETHA_SECRET_KEY and THETHA_MASTER_KEY must be set in production")
    # Development convenience only. The security scanner flags this file.
    path = os.path.join(app.instance_path, "dev_keys.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            keys = json.load(fh)
    else:
        keys = {"SECRET_KEY": secrets.token_urlsafe(48), "MASTER_KEY": generate_master_key()}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(keys, fh)
        app.logger.warning("Generated development keys in %s. Do NOT use in production.", path)
    app.config.update(SECRET_KEY=secret or keys["SECRET_KEY"], MASTER_KEY=master or keys["MASTER_KEY"])


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    env_name = os.environ.get("THETHA_ENV", "development")
    app.config.from_mapping(
        ENV_NAME=env_name,
        DATABASE=os.environ.get("THETHA_DB", os.path.join(app.instance_path, "thetha.db")),
        MAX_CONTENT_LENGTH=64 * 1024,               # reject oversized bodies (DoS)
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=env_name == "production",
        SESSION_COOKIE_NAME="t_sid",                 # nothing that hints at GBV on a shared phone
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
        LOCKOUT_THRESHOLD=5,
        LOCKOUT_MINUTES=15,
        CALLBACK_RETENTION_DAYS=30,
        EVENT_RETENTION_DAYS=365,
        RATE_LIMITS={                                # bucket: (requests, seconds)
            "chat": (30, 60),
            "login": (10, 300),
            "register": (5, 3600),
            "callback": (5, 3600),
            "write": (60, 300),
        },
    )
    if test_config:
        app.config.update(test_config)
    _load_keys(app)
    app.extensions["vault"] = Vault(app.config["MASTER_KEY"])

    security.init_app(app)
    db.init_app(app)

    from . import routes
    app.register_blueprint(routes.bp)
    app.cli.add_command(routes.create_counsellor_command)
    return app
