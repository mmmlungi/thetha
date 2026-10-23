"""Field-level encryption for sensitive data at rest.

Every sensitive value (journal entries, safety plans, phone numbers, aliases)
is encrypted with AES-256-GCM before it touches the database. Nothing
sensitive is ever stored in clear text (CWE-312).

* A single master key (from the THETHA_MASTER_KEY env var) is split with HKDF
  into an encryption key and a separate blind-index key.
* Each ciphertext is bound to a "context" (e.g. ``journal:42``) through GCM's
  associated data, so a ciphertext copied into another user's row will fail
  to decrypt instead of leaking.
* Usernames are never stored; we store an HMAC "blind index" so we can still
  look a user up at login.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = "v1:"
NONCE_LEN = 12
TAG_LEN = 16


class DecryptionError(Exception):
    """Raised when a ciphertext is tampered with, malformed or used out of context."""


def generate_master_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _derive(master: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(master)


class Vault:
    def __init__(self, master_key: str):
        try:
            master = base64.urlsafe_b64decode(master_key.encode("ascii"))
        except (binascii.Error, ValueError, AttributeError) as exc:
            raise ValueError("master key must be url-safe base64") from exc
        if len(master) != 32:
            raise ValueError("master key must decode to exactly 32 bytes")
        self._aead = AESGCM(_derive(master, b"thetha/enc/v1"))
        self._index_key = _derive(master, b"thetha/index/v1")

    def encrypt(self, plaintext: str, context: str) -> str:
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be str")
        nonce = os.urandom(NONCE_LEN)
        ct = self._aead.encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
        return PREFIX + base64.urlsafe_b64encode(nonce + ct).decode("ascii")

    def decrypt(self, token: str, context: str) -> str:
        if not isinstance(token, str) or not token.startswith(PREFIX):
            raise DecryptionError("value is not an encrypted v1 token")
        try:
            raw = base64.urlsafe_b64decode(token[len(PREFIX):].encode("ascii"))
            if len(raw) < NONCE_LEN + TAG_LEN:
                raise DecryptionError("ciphertext too short")
            pt = self._aead.decrypt(raw[:NONCE_LEN], raw[NONCE_LEN:], context.encode("utf-8"))
            return pt.decode("utf-8")
        except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
            raise DecryptionError("ciphertext rejected") from exc

    def encrypt_json(self, data, context: str) -> str:
        return self.encrypt(json.dumps(data, separators=(",", ":")), context)

    def decrypt_json(self, token: str, context: str):
        return json.loads(self.decrypt(token, context))

    def blind_index(self, value: str) -> str:
        normalized = value.strip().lower().encode("utf-8")
        return hmac.new(self._index_key, normalized, hashlib.sha256).hexdigest()


def looks_encrypted(value) -> bool:
    """Structural check used by the vulnerability scanner (no key needed)."""
    if not isinstance(value, str) or not value.startswith(PREFIX):
        return False
    try:
        raw = base64.urlsafe_b64decode(value[len(PREFIX):].encode("ascii"))
    except (binascii.Error, ValueError):
        return False
    return len(raw) >= NONCE_LEN + TAG_LEN + 1
