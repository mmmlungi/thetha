# Thetha: a safe, private GBV support chatbot for South Africa

*Thetha* means "speak" in isiZulu and isiXhosa.

## 1. The need

South Africa has one of the highest rates of gender-based violence in the world. Our community research points to four practical barriers that stop survivors from getting help:

| Need / want in the community | What gets in the way | What Thetha does |
|---|---|---|
| "I don't know if what's happening to me counts as abuse." | Emotional, financial and online abuse aren't widely understood as abuse. | Explains the Domestic Violence Act in plain language. |
| "I don't know where to start: police, court, clinic?" | Information is scattered and full of legal jargon. | Step-by-step guides: protection orders, opening a case, PEP within 72 hours after rape. |
| "He checks my phone." | Fear of being found out on a shared or monitored phone. | Quick exit (button or Esc twice), neutral tab title, no chat history saved, no browser caching. |
| "The court wants dates and details I can't remember." | No safe place to keep evidence. | An encrypted incident journal you can export for a lawyer or court. |
| "I want to talk to a person, but not right now." | Calling at the wrong time can be dangerous. | Request a callback with a chosen safe time and voicemail preference. |
| NGOs and government lack data on where help is needed. | Survivors' privacy must not be put at risk to get that data. | Anonymous dashboard by need, risk level, province and language. |

## 2. The product

- **Multilingual chatbot**: English, isiZulu, isiXhosa, Afrikaans and Sesotho. It recognises 19 needs, including emergency, self-harm, sexual assault, protection orders, shelters, children, and financial and online abuse.
- **Danger assessment**: 6 yes/no questions weighted by lethality research (prior strangulation alone means high risk). It gives a low, medium or high result with next steps.
- **Safety override**: a message like "he has a knife" or "I want to die" gets police or crisis numbers immediately, even in the middle of another conversation.
- **Encrypted journal and safety plan** for survivors with an anonymous account (nickname only, no email or phone needed).
- **Safe callback requests**, plus a **counsellor dashboard** with an audit trail.
- **POPIA rights**: download all my data, and permanently delete everything.

## 3. Mapping to the judging criteria

| Criterion | How Thetha meets it |
|---|---|
| **Product** | Working web app: chat, risk check, journal, safety plan, callbacks, counsellor dashboard, data export and erasure. |
| **Creativity** | Quick exit, neutral tab and cookie names, a code word in the safety plan, and voicemail preference for callbacks. All are designed around the abuser's phone as the threat. |
| **Usability** | Quick-reply buttons, five languages, typo tolerance, works on small phones, light and dark mode, no app install, very little data used. |
| **Sustainability** | No AI API costs: the rule-based engine runs on a tiny server. Open, testable code that NGOs can host themselves. Automatic data purging keeps storage small. |
| **Impact** | Turns confusion into concrete steps (court, police, clinic within 72 hours). Anonymous statistics show NGOs which needs and provinces are growing. |
| **Presentation** | Live demo script below. Security report and test results generated automatically. |
| **Intelligence** | Weighted multilingual intent scoring, fuzzy matching for typos, language detection, a multi-turn risk assessment, and safety overrides. |

## 4. Data management and security

### Sensitive data is never stored in clear text (CWE-312)

| Data | How it's stored |
|---|---|
| Journal entries, safety plans | AES-256-GCM, bound to the user ID (a row copied to another user fails to decrypt) |
| Callback name, phone number, notes | AES-256-GCM, bound to the request reference |
| Username | Only an HMAC-SHA256 *blind index*; the display name is encrypted |
| Password | scrypt hash |
| Chat messages | **Not stored at all**; only an anonymous event (need, risk level, language, province, day) |

Keys come from environment variables. The app **refuses to start in production without them**, and HKDF derives separate encryption and index keys. SQLite `secure_delete` plus `VACUUM` make deleted data unrecoverable from the file.

### Other controls

CSRF tokens · strict Content Security Policy (no inline scripts) · XSS-safe rendering · parameterised SQL · rate limiting · account lockout after 5 failures · same error message for wrong username or password (no user enumeration) · session-fixation protection · open-redirect protection · authorisation checks so users can't access each other's records · 15-minute sessions · HttpOnly/SameSite=Strict/Secure cookies · `Cache-Control: no-store` · phone numbers and emails redacted from logs · 64 KB request limit · audit log.

### Vulnerability scan

```bash
python tools/security_scan.py --canary "some secret text"
```

The scan checks:
- that every sensitive column holds ciphertext;
- that no phone numbers or emails appear anywhere in the database, including the raw file's freed pages;
- password hashing, cookie flags, secret strength and security headers;
- **Bandit** static analysis.

It writes `reports/security_report.md` and exits with code 1 on failure, so it can block a release in CI. Current result: **0 failures, 0 Bandit issues** (one expected warning: development keys are in use locally).

## 5. Testing: positive and negative

```bash
python -m pytest              # all 133 tests
python -m pytest -m positive  # 56: valid use works
python -m pytest -m negative  # 77: bad, malicious or unauthorised input is rejected
python -m pytest -m security  # 25: encryption-at-rest and vulnerability checks
```

| Positive examples | Negative examples |
|---|---|
| Recognises needs in 5 languages | Gibberish gets a safe fallback with a helpline |
| Emergency returns 10111 first | Danger in the middle of the risk check overrides it |
| Journal saves, then reads back decrypted | Future dates, bad types and empty text are rejected |
| Counsellor sees the decrypted callback | A survivor gets 403 on the dashboard |
| Export and delete my data | Delete with the wrong password removes nothing |
| Scanner passes on a clean database | Scanner **catches planted clear text**, plain passwords and phone numbers |
| Encrypt/decrypt round trip | Tampered ciphertext, wrong key, swapped rows and malformed tokens are rejected |
| Security headers and cookie flags present | Missing or forged CSRF token, SQL injection, XSS, open redirect, rate-limit abuse, lockout, oversized body, production start without keys |

## 6. Run it

**Easiest:** double-click `start.bat`. It loads demo data, starts the server and opens the browser.

Or from any folder:

```bash
pip install -r requirements.txt
python C:\Users\27848\thetha\run.py --seed   # http://127.0.0.1:5000
```

(`python -m flask --app app run` only works from inside the `thetha` folder.)

Demo logins (seeded): `counsellor` / `Demo2026pass` and `demo` / `Demo2026pass`.
Create real staff accounts with `python -m flask --app app create-counsellor <name>`.
Purge expired data daily with `python -m flask --app app purge-expired`, for example from a cron job.

Production: set `THETHA_ENV=production`, `THETHA_SECRET_KEY` and `THETHA_MASTER_KEY` (generate it with `python -c "from app.crypto import generate_master_key as g; print(g())"`). Serve it over HTTPS behind gunicorn or waitress.

### Free hosting on PythonAnywhere

1. Sign up for a free **Beginner** account at pythonanywhere.com.
2. **Consoles → Bash**, then run:
   ```bash
   git clone https://github.com/mmmlungi/thetha.git
   bash ~/thetha/deploy/pythonanywhere_setup.sh --demo
   ```
   With `--demo` you choose a private password for the `demo` and `counsellor` accounts. The README password is refused in production.
   **Back up `~/.thetha_keys`**: if it's lost, the encrypted data can never be read again.
3. **Web → Add a new web app → Manual configuration**, and pick the Python version the script printed.
4. In the Web tab:
   - Open the **WSGI configuration file** link and replace its contents with `deploy/pythonanywhere_wsgi.py`.
   - Under **Static files**, add URL `/static/` → directory `/home/<username>/thetha/app/static`.
   - Turn on **Force HTTPS**.
   - Press **Reload**.
5. Open `https://<username>.pythonanywhere.com`.

To update later: `cd ~/thetha && git pull`, then press **Reload**. Free web apps must be extended in the Web tab every 3 months.

## 7. Suggested 5-minute demo

1. **The problem** (30s): the barriers in section 1.
2. **Chat** (90s): type `Sawubona ngiyashaywa` → *Check my risk* → answer *yes* to strangulation → high-risk result. Then type `he has a knife` and police numbers appear first.
3. **Quick exit** (15s): press Esc twice and the browser jumps to a weather search.
4. **Journal** (45s): log in as `demo`, add an entry, then show in a database viewer that it is unreadable ciphertext.
5. **Counsellor** (45s): request a callback, log in as `counsellor`, show the decrypted number and the anonymous province statistics.
6. **Proof** (60s): run `pytest -m negative` and `tools/security_scan.py` live.

## 8. Roadmap

- WhatsApp and USSD channels for users with no data or basic phones.
- Translations reviewed by native speakers. Current non-English phrases are short and **must be checked before launch**.
- A Thuthuzela Care Centre and police-station locator.
- Redis-backed rate limiting and Postgres when running more than one server.
- Partnerships with the GBV Command Centre and NGOs. **Verify all helpline numbers with each organisation before launch.**

> Thetha gives information and support. It doesn't replace police, medical or legal professionals.
