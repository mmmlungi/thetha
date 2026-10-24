# Thetha security scan

**20 pass · 1 warn · 0 fail**

| Result | Check | Detail |
|---|---|---|
| PASS | `encrypted:users.alias_enc` | 3 rows, all AES-GCM ciphertext |
| PASS | `encrypted:journal_entries.payload_enc` | 7 rows, all AES-GCM ciphertext |
| PASS | `encrypted:safety_plans.payload_enc` | 1 rows, all AES-GCM ciphertext |
| PASS | `encrypted:callback_requests.payload_enc` | 3 rows, all AES-GCM ciphertext |
| PASS | `password-hashing` | 3 scrypt/pbkdf2 hashes |
| PASS | `username-blind-index` | usernames stored only as HMAC-SHA256 |
| PASS | `pii-pattern-scan` | no phone numbers or emails in any column |
| PASS | `raw-file-scan` | no PII patterns in raw DB file |
| PASS | `secret-key-strength` | 64 chars |
| WARN | `dev-keys` | instance/dev_keys.json exists; set THETHA_MASTER_KEY/THETHA_SECRET_KEY in production |
| PASS | `cookie-httponly` | True |
| PASS | `cookie-samesite` | Strict |
| PASS | `cookie-secure` | False (env=development) |
| PASS | `debug-mode` | False |
| PASS | `max-body-size` | 65536 |
| PASS | `header:Content-Security-Policy` | default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none' |
| PASS | `header:X-Frame-Options` | DENY |
| PASS | `header:X-Content-Type-Options` | nosniff |
| PASS | `header:Referrer-Policy` | no-referrer |
| PASS | `header:Cache-Control` | no-store, max-age=0 |
| PASS | `bandit` | no issues in 1243 lines of code |
