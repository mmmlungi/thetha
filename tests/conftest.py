import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import create_app  # noqa: E402
from app.crypto import generate_master_key  # noqa: E402
from app.security import limiter  # noqa: E402

PASSWORD = "Safe2026pass"


@pytest.fixture
def make_app(tmp_path):
    def _make(**overrides):
        limiter.reset()
        cfg = {"TESTING": True, "DATABASE": str(tmp_path / "test.db"),
               "SECRET_KEY": "s" * 48, "MASTER_KEY": generate_master_key()}
        cfg.update(overrides)
        return create_app(cfg)
    return _make


@pytest.fixture
def app(make_app):
    return make_app()


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client, path="/"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def register(client, username="lindiwe", password=PASSWORD):
    token = csrf(client, "/register")
    return client.post("/register", data={"_csrf": token, "username": username,
                                          "password": password, "confirm": password})


def login(client, username="lindiwe", password=PASSWORD):
    token = csrf(client, "/login")
    return client.post("/login", data={"_csrf": token, "username": username, "password": password})


def chat(client, message, province=None, token=None):
    token = token or csrf(client)
    return client.post("/api/chat", json={"message": message, "province": province},
                       headers={"X-CSRF-Token": token})


def add_journal(client, **fields):
    data = {"date": "2026-10-01", "type": "physical", "description": "He pushed me against the wall",
            "location": "Home", "injuries": "Bruised arm", "witnesses": "Neighbour"}
    data.update(fields)
    data["_csrf"] = csrf(client, "/journal")
    return client.post("/journal", data=data)


def make_counsellor(app, username="counsel1", password="Couns3lPass"):
    result = app.test_cli_runner().invoke(args=["create-counsellor", username, "--password", password])
    assert result.exit_code == 0, result.output
