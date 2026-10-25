# Dudu: a safe, private GBV support chatbot for South Africa

*Dudu* comes from *duduza*, "to comfort" in isiZulu and isiXhosa. Its colours are taken from its logo: teal for connection, warm orange for compassion and green for hope.

## 1. The need

South Africa has one of the highest rates of gender-based violence in the world. Our community research points to four practical barriers that stop survivors from getting help:

| Need / want in the community | What gets in the way | What Dudu does |
|---|---|---|
| "I don't know if what's happening to me counts as abuse." | Emotional, financial and online abuse aren't widely understood as abuse. | Explains the Domestic Violence Act in plain language. |
| "I don't know where to start: police, court, clinic?" | Information is scattered and full of legal jargon. | Step-by-step guides: protection orders, opening a case, PEP within 72 hours after rape. |
| "He checks my phone." | Fear of being found out on a shared or monitored phone. | **Slayza** quick-exit button (or Esc twice), neutral tab title, no chat history saved, no browser caching. |
| "The court wants dates and details I can't remember." | No safe place to keep evidence. | An encrypted incident journal you can export for a lawyer or court. |
| "I want to talk to a person, but not right now." | Calling at the wrong time can be dangerous. | Request a callback with a chosen safe time and voicemail preference. |
| NGOs and government lack data on where help is needed. | Survivors' privacy must not be put at risk to get that data. | Anonymous dashboard by need, risk level, province and language. |

## 2. The product

- **Multilingual chatbot**: English, isiZulu, isiXhosa, Afrikaans and Sesotho. It recognises 19 needs, including emergency, self-harm, sexual assault, protection orders, shelters, children, and financial and online abuse.
- **Danger assessment**: 6 yes/no questions weighted by lethality research (prior strangulation alone means high risk). It gives a low, medium or high result with next steps.
- **Safety override**: a message like "he has a knife" or "I want to die" gets police or crisis numbers immediately, even in the middle of another conversation.
- **Encrypted journal and safety plan** for survivors with an anonymous account (nickname only, no email or phone needed).
- **Evidence in the journal**: photos, videos and voice notes recorded right in the browser. Every file is encrypted, checked by its real contents (a renamed `.exe` or an `.svg` is refused), and given a **SHA-256 fingerprint** so a court can check it hasn't been changed. Injury photos stay blurred until the person taps to look.
- **Workplace incidents**: choose "Workplace" and record the employer, the person's role, whether it was reported to HR, a union or the CCMA, the reference number and the impact on work. The chatbot explains workplace harassment rights and the Protection from Harassment Act.
- **Printable exports**: a **PDF report** (incidents in date order, photos embedded, fingerprints listed), a **printable page** (or "Save as PDF" on a phone), and a **ZIP evidence pack** with the original files. The safety plan is deliberately left out of these, because court papers are shown to the other side.
- **Installable app (PWA)**: add Dudu to the home screen on Android, iPhone, iPad, Windows, Mac and Chromebook. It opens full screen like an app, and offline it still shows the emergency numbers.
- **Safe callback requests**, plus a **counsellor dashboard** with an audit trail.
- **POPIA rights**: download all my data, and permanently delete everything.

## 3. Mapping to the judging criteria

| Criterion | How Dudu meets it |
|---|---|
| **Product** | Working web app, installable on any phone: chat, risk check, journal with photo, video and voice evidence, workplace incidents, safety plan, callbacks, counsellor dashboard, PDF and print exports, data erasure. |
| **Creativity** | A discreet "Slayza" quick-exit button, an animated four-scene story told in illustrations, liquid-glass design, neutral tab and cookie names, a code word in the safety plan, and voicemail preference for callbacks. All are designed around the abuser's phone as the threat. |
| **Usability** | Warm, human copy; a skippable story that explains Dudu in 20 seconds; quick-reply buttons, five languages, typo tolerance, works on small phones, light and dark mode, no app install, very little data used. |
| **Sustainability** | No AI API costs: the rule-based engine runs on a tiny server. Open, testable code that NGOs can host themselves. Automatic data purging keeps storage small. |
| **Impact** | Turns confusion into concrete steps (court, police, clinic within 72 hours). Anonymous statistics show NGOs which needs and provinces are growing. |
| **Presentation** | Live demo script below. Security report and test results generated automatically. |
| **Intelligence** | Weighted multilingual intent scoring, fuzzy matching for typos, language detection, a multi-turn risk assessment, and safety overrides. |

## 4. Data management and security

### Sensitive data is never stored in clear text (CWE-312)

| Data | How it's stored |
|---|---|
| Journal entries, safety plans | AES-256-GCM, bound to the user ID (a row copied to another user fails to decrypt) |
| Photos, videos, voice notes | AES-256-GCM files on disk, bound to owner and file name; original name, type and SHA-256 encrypted in the database |
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
- that every evidence file on disk is encrypted (no readable photo, video or audio);
- password hashing, cookie flags, secret strength and security headers;
- **Bandit** static analysis.

It writes `reports/security_report.md` and exits with code 1 on failure, so it can block a release in CI. Current result: **0 failures, 0 Bandit issues** (one expected warning: development keys are in use locally).

## 5. Testing: positive and negative

```bash
python -m pytest              # all 176 tests
python -m pytest -m positive  # 72: valid use works
python -m pytest -m negative  # 104: bad, malicious or unauthorised input is rejected
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
| Photo, video and voice note saved, encrypted, playable | SVG, HTML, `.exe` or PDF disguised as a photo is refused; nothing is stored |
| PDF, printable page and ZIP with matching fingerprints | Another user can't open or delete my files; a tampered or swapped file is refused |
| Workplace details saved and printed | Oversized files, too many files and a full quota are refused |

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

To update later:
```bash
cd ~/thetha && git pull
python3.13 -m pip install --user -r requirements.txt   # use the Python version your web app uses
```
then press **Reload**. Free web apps must be extended in the Web tab every 3 months.

Evidence files are stored in `~/thetha-data/media`, next to the database and outside the code. The free plan has 512 MB of disk in total, so each person's evidence is capped at 150 MB (change `MEDIA_USER_QUOTA` in `app/__init__.py`).

## 7. Suggested 5-minute demo

1. **The problem** (30s): the barriers in section 1.
2. **Chat** (90s): type `Sawubona ngiyashaywa` → *Check my risk* → answer *yes* to strangulation → high-risk result. Then type `he has a knife` and police numbers appear first.
3. **Slayza** (15s): tap Slayza or press Esc twice and the browser jumps to a weather search.
4. **Journal** (60s): log in as `demo`. Open the workplace entry and tap the blurred screenshot. Record a 5-second voice note and save it. Then go to *My data* and download the PDF report.
5. **Counsellor** (45s): request a callback, log in as `counsellor`, show the decrypted number and the anonymous province statistics.
6. **Proof** (60s): run `pytest -m negative` and `tools/security_scan.py` live.

## 8. Phones, tablets and app stores

Dudu is a **Progressive Web App (PWA)**: one codebase that runs in any modern browser and can be installed like an app.

| Platform | How people get it |
|---|---|
| Android (Samsung, Xiaomi, Oppo and others) | Open the site in Chrome, then tap **Add Dudu to your home screen** (or ⋮ → *Install app*) |
| iPhone and iPad | Open in Safari → **Share** → **Add to Home Screen** |
| Huawei (no Google services) | Open in Huawei Browser → menu → **Add to home screen** |
| Windows, Mac, Chromebook | Chrome or Edge: install icon in the address bar |

Store listings, if needed later, can reuse the same site without rewriting the app:
- **Google Play**: wrap the PWA as a Trusted Web Activity with PWABuilder or Bubblewrap ($25 one-off developer fee).
- **Huawei AppGallery**: the same Android package, built with the WebView fallback.
- **Apple App Store**: wrap with Capacitor. It needs a Mac, a $99 a year developer account, and extra native features, because Apple often rejects apps that are only a website.

Privacy note: an installed icon is visible on the home screen. People who share a phone with an abuser may prefer to use Dudu in the browser instead.

## 9. Roadmap

- WhatsApp and USSD channels for users with no data or basic phones.
- Translations reviewed by native speakers. Current non-English phrases are short and **must be checked before launch**.
- A Thuthuzela Care Centre and police-station locator.
- Redis-backed rate limiting and Postgres when running more than one server.
- Partnerships with the GBV Command Centre and NGOs. **Verify all helpline numbers with each organisation before launch.**

> Dudu gives information and support. It doesn't replace police, medical or legal professionals.
