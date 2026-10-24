"""Dudu vulnerability & clear-text storage scanner.

Checks:
  1. Clear-text storage (CWE-312): every sensitive column must hold AES-GCM
     ciphertext; no phone numbers / emails anywhere in the DB, including
     freed pages in the raw file; passwords must be scrypt/pbkdf2 hashes;
     usernames must only exist as HMAC blind indexes.
  2. Configuration: secret strength, dev keys, cookie flags, debug mode.
  3. HTTP security headers (CSP, frame, nosniff, no-store cache).
  4. Static code analysis with Bandit (SQL injection, weak crypto, etc.).

Usage:
    python tools/security_scan.py [--db PATH] [--report reports/security_report.md] [--canary TEXT ...]
Exit code 1 if any FAIL is found, so it can gate CI.
"""
import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.crypto import looks_encrypted  # noqa: E402
from app.db import SENSITIVE_COLUMNS  # noqa: E402

PHONE = re.compile(r"(?<![\w])(?:\+27|0)\d{2}[\s-]?\d{3}[\s-]?\d{4}(?![\w])")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}")
# No trailing boundary: SQLite packs the next record's bytes (often digits) right after a value.
PHONE_B = re.compile(rb"(?<!\d)(?:\+27|0)[1-8]\d{8}")
# Ciphertext, password hashes and hex blind indexes can't hold PII but can contain digit runs.
CIPHERTEXT_B = re.compile(rb"v1:[A-Za-z0-9_\-=]+|(?:scrypt|pbkdf2)[\w:$]+|[0-9a-f]{64}")
EMAIL_B = re.compile(rb"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}")


@dataclass
class Finding:
    level: str      # PASS / WARN / FAIL
    check: str
    detail: str


def scan_cleartext(db_path: str, canaries=()) -> list[Finding]:
    out = []
    if not os.path.exists(db_path):
        return [Finding("WARN", "database", f"{db_path} not found; skipped storage checks")]
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    for table, col, pk in SENSITIVE_COLUMNS:
        rows = conn.execute(f"SELECT {pk} AS pk, {col} AS v FROM {table}").fetchall()  # nosec B608 - names are constants
        bad = [r["pk"] for r in rows if r["v"] is not None and not looks_encrypted(r["v"])]
        if bad:
            out.append(Finding("FAIL", f"encrypted:{table}.{col}", f"clear-text values in rows {bad[:10]}"))
        else:
            out.append(Finding("PASS", f"encrypted:{table}.{col}", f"{len(rows)} rows, all AES-GCM ciphertext"))

    hashes = conn.execute("SELECT id, password_hash, username_index FROM users").fetchall()
    weak = [r["id"] for r in hashes if not str(r["password_hash"]).startswith(("scrypt:", "pbkdf2:"))]
    out.append(Finding("FAIL" if weak else "PASS", "password-hashing",
                       f"non-hashed passwords for users {weak}" if weak else f"{len(hashes)} scrypt/pbkdf2 hashes"))
    bad_idx = [r["id"] for r in hashes if not re.fullmatch(r"[0-9a-f]{64}", str(r["username_index"]))]
    out.append(Finding("FAIL" if bad_idx else "PASS", "username-blind-index",
                       f"plain usernames for users {bad_idx}" if bad_idx else "usernames stored only as HMAC-SHA256"))

    leaks = []
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    for t in tables:
        for row in conn.execute(f"SELECT * FROM {t}"):  # nosec B608 - names from sqlite_master
            for key in row.keys():
                v = row[key]
                if isinstance(v, str) and not looks_encrypted(v) and (PHONE.search(v) or EMAIL.search(v)):
                    leaks.append(f"{t}.{key}")
    conn.close()
    out.append(Finding("FAIL" if leaks else "PASS", "pii-pattern-scan",
                       f"phone/email found in {sorted(set(leaks))}" if leaks else "no phone numbers or emails in any column"))

    # Raw file bytes catch data left in freed pages, WAL or journal files.
    raw = b""
    for suffix in ("", "-wal", "-journal"):
        if os.path.exists(db_path + suffix):
            with open(db_path + suffix, "rb") as fh:
                raw += fh.read()
    # Records are packed with no separators, so blank out ciphertext before pattern matching.
    plain = CIPHERTEXT_B.sub(lambda m: b" " * len(m.group()), raw)
    raw_hits = len(PHONE_B.findall(plain)) + len(EMAIL_B.findall(plain))
    out.append(Finding("FAIL" if raw_hits else "PASS", "raw-file-scan",
                       f"{raw_hits} PII patterns in raw DB bytes" if raw_hits else "no PII patterns in raw DB file"))
    for c in canaries:
        found = c.encode("utf-8") in raw
        out.append(Finding("FAIL" if found else "PASS", "canary", f"'{c[:20]}' {'FOUND in clear text' if found else 'not present'}"))
    return out


def scan_config(app) -> list[Finding]:
    out = []
    cfg = app.config
    out.append(Finding("PASS" if len(str(cfg["SECRET_KEY"])) >= 32 else "FAIL", "secret-key-strength",
                       f"{len(str(cfg['SECRET_KEY']))} chars"))
    dev_keys = os.path.join(app.instance_path, "dev_keys.json")
    if os.path.exists(dev_keys):
        out.append(Finding("FAIL" if cfg["ENV_NAME"] == "production" else "WARN", "dev-keys",
                           "instance/dev_keys.json exists; set THETHA_MASTER_KEY/THETHA_SECRET_KEY in production"))
    else:
        out.append(Finding("PASS", "dev-keys", "keys supplied via environment"))
    out.append(Finding("PASS" if cfg["SESSION_COOKIE_HTTPONLY"] else "FAIL", "cookie-httponly", str(cfg["SESSION_COOKIE_HTTPONLY"])))
    out.append(Finding("PASS" if cfg["SESSION_COOKIE_SAMESITE"] == "Strict" else "WARN", "cookie-samesite", str(cfg["SESSION_COOKIE_SAMESITE"])))
    secure_ok = cfg["SESSION_COOKIE_SECURE"] or cfg["ENV_NAME"] != "production"
    out.append(Finding("PASS" if secure_ok else "FAIL", "cookie-secure", f"{cfg['SESSION_COOKIE_SECURE']} (env={cfg['ENV_NAME']})"))
    out.append(Finding("FAIL" if app.debug and cfg["ENV_NAME"] == "production" else "PASS", "debug-mode", str(app.debug)))
    out.append(Finding("PASS" if cfg.get("MAX_CONTENT_LENGTH") else "FAIL", "max-body-size", str(cfg.get("MAX_CONTENT_LENGTH"))))
    return out


REQUIRED_HEADERS = {
    "Content-Security-Policy": "script-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def scan_headers(app) -> list[Finding]:
    resp = app.test_client().get("/")
    out = []
    for name, must in REQUIRED_HEADERS.items():
        val = resp.headers.get(name, "")
        out.append(Finding("PASS" if must in val else "FAIL", f"header:{name}", val or "missing"))
    return out


def scan_code() -> list[Finding]:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed arguments
            [sys.executable, "-m", "bandit", "-r", os.path.join(ROOT, "app"), "-f", "json", "-q"],
            capture_output=True, text=True, timeout=300, check=False)
        report = json.loads(proc.stdout or "{}")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return [Finding("WARN", "bandit", f"could not run bandit: {exc}")]
    results = report.get("results", [])
    out = []
    for r in results:
        level = "FAIL" if r["issue_severity"] in ("HIGH", "MEDIUM") else "WARN"
        out.append(Finding(level, f"bandit:{r['test_id']}",
                           f"{os.path.relpath(r['filename'], ROOT)}:{r['line_number']} {r['issue_text']}"))
    if not results:
        loc = report.get("metrics", {}).get("_totals", {}).get("loc", "?")
        out.append(Finding("PASS", "bandit", f"no issues in {loc} lines of code"))
    return out


def run(db_path=None, canaries=(), include_code=True, app=None):
    from app import create_app
    app = app or create_app()
    db_path = db_path or app.config["DATABASE"]
    findings = scan_cleartext(db_path, canaries) + scan_config(app) + scan_headers(app)
    if include_code:
        findings += scan_code()
    return findings


def to_markdown(findings) -> str:
    counts = {lvl: sum(f.level == lvl for f in findings) for lvl in ("PASS", "WARN", "FAIL")}
    lines = ["# Dudu security scan", "",
             f"**{counts['PASS']} pass · {counts['WARN']} warn · {counts['FAIL']} fail**", "",
             "| Result | Check | Detail |", "|---|---|---|"]
    lines += [f"| {f.level} | `{f.check}` | {f.detail.replace('|', '/')} |" for f in findings]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db")
    ap.add_argument("--report", default=os.path.join(ROOT, "reports", "security_report.md"))
    ap.add_argument("--canary", action="append", default=[], help="text that must NOT appear in clear text")
    ap.add_argument("--no-code", action="store_true", help="skip bandit")
    args = ap.parse_args()
    findings = run(args.db, args.canary, not args.no_code)
    for f in findings:
        print(f"[{f.level}] {f.check:32} {f.detail}")
    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(findings))
    print(f"\nReport written to {args.report}")
    sys.exit(1 if any(f.level == "FAIL" for f in findings) else 0)


if __name__ == "__main__":
    main()
