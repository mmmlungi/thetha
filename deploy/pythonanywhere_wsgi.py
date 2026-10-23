# Paste this whole file into PythonAnywhere's WSGI configuration file
# (Web tab -> "WSGI configuration file" link), replacing everything in it.
import os
import sys

HOME = os.path.expanduser("~")
APP_DIR = os.path.join(HOME, "thetha")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

# Keys created by deploy/pythonanywhere_setup.sh, kept outside the repo.
with open(os.path.join(HOME, ".thetha_keys"), encoding="utf-8") as fh:
    for line in fh:
        key, _, value = line.strip().partition("=")
        if key:
            os.environ.setdefault(key, value)
os.environ.setdefault("THETHA_ENV", "production")
os.environ.setdefault("THETHA_DB", os.path.join(HOME, "thetha-data", "thetha.db"))

from app import create_app  # noqa: E402

application = create_app()
