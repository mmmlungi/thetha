#!/bin/bash
# One-time setup on PythonAnywhere (run in a PythonAnywhere Bash console):
#   bash ~/thetha/deploy/pythonanywhere_setup.sh            # app only
#   bash ~/thetha/deploy/pythonanywhere_setup.sh --demo     # app + demo data for judges
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PY:-}"   # override with e.g. PY=python3.12 bash deploy/pythonanywhere_setup.sh
if [ -z "$PY" ]; then
  for v in 3.13 3.12 3.11 3.10; do
    if command -v "python$v" >/dev/null 2>&1; then PY="python$v"; break; fi
  done
fi
[ -n "$PY" ] || { echo "No Python 3.10+ found"; exit 1; }
echo "Using $PY (choose the same version when you create the web app)"

$PY -m pip install --user -q -r requirements.txt

# Keys live outside the repo so 'git pull' never touches them.
KEYS="$HOME/.thetha_keys"
if [ ! -f "$KEYS" ]; then
  $PY -c "import secrets,base64,os; print('THETHA_SECRET_KEY='+secrets.token_urlsafe(48)); print('THETHA_MASTER_KEY='+base64.urlsafe_b64encode(os.urandom(32)).decode())" > "$KEYS"
  chmod 600 "$KEYS"
  echo "Created $KEYS. BACK IT UP: without THETHA_MASTER_KEY the encrypted data can never be read."
fi

mkdir -p "$HOME/thetha-data"
export THETHA_ENV=production THETHA_DB="$HOME/thetha-data/thetha.db"
set -a; . "$KEYS"; set +a

if [ "${1:-}" = "--demo" ]; then
  read -r -s -p "Choose a password for the demo accounts (8+ chars, letters and numbers): " THETHA_DEMO_PASSWORD
  echo
  export THETHA_DEMO_PASSWORD
  $PY tools/seed_demo.py --demo-in-production
else
  $PY -c "from app import create_app; create_app()" && echo "Database ready at $THETHA_DB"
fi

echo
echo "Next: Web tab -> Add a new web app -> Manual configuration -> $PY"
echo "Then paste deploy/pythonanywhere_wsgi.py into the WSGI configuration file."
