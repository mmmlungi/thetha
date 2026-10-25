"""Encrypted evidence files for the journal: photos, videos and voice notes.

* The file type is decided from the file's first bytes, never from the name or
  the type the browser claims, so a renamed .exe or an .svg/.html can't get in.
* Each file gets a SHA-256 fingerprint at upload. It goes into the exports so a
  court can check the file hasn't been changed since it was recorded.
* Files are AES-256-GCM encrypted to disk, bound to their owner and file name,
  and only ever decrypted in memory for their owner.
"""
import os
import re
import secrets

from flask import current_app
from werkzeug.utils import secure_filename

from .crypto import DecryptionError
from .security import ValidationError

MAGIC = b"DUDU1"  # header of every stored file; the scanner checks for it

ALLOWED_DESCRIPTION = "photos (JPEG, PNG, GIF, WebP, HEIC), videos (MP4, MOV, WebM) or voice notes (M4A, MP3, OGG, WAV, WebM)"


def sniff(head: bytes, declared: str = "") -> tuple[str, str] | None:
    """Return (mime, kind) from magic bytes, or None if not an allowed media file."""
    audio_hint = (declared or "").startswith("audio/")
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "image"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "image"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif", "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp", "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "audio/wav", "audio"
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"hevc"):
            return "image/heic", "image"
        if brand in (b"M4A ", b"M4B ") or audio_hint:
            return "audio/mp4", "audio"
        if brand == b"qt  ":
            return "video/quicktime", "video"
        return "video/mp4", "video"
    if head.startswith(b"\x1a\x45\xdf\xa3"):  # WebM / Matroska (voice notes from Chrome, Android)
        return ("audio/webm", "audio") if audio_hint else ("video/webm", "video")
    if head.startswith(b"OggS"):
        return "audio/ogg", "audio"
    if head.startswith(b"ID3") or head[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "audio/mpeg", "audio"
    if head[:2] in (b"\xff\xf1", b"\xff\xf9"):
        return "audio/aac", "audio"
    return None


def media_dir() -> str:
    path = current_app.config["MEDIA_DIR"]
    os.makedirs(path, exist_ok=True)
    return path


def _ctx(uid: int, stored_name: str) -> str:
    return f"media:{uid}:{stored_name}"


def meta_ctx(uid: int, stored_name: str) -> str:
    return f"media-meta:{uid}:{stored_name}"


def read_uploads(files, used_bytes: int, existing_count: int = 0) -> list[dict]:
    """Validate uploads fully before anything is written. Returns prepared items."""
    cfg = current_app.config
    files = [f for f in files if f and f.filename]
    if existing_count + len(files) > cfg["MEDIA_MAX_FILES_PER_ENTRY"]:
        raise ValidationError(f"You can attach up to {cfg['MEDIA_MAX_FILES_PER_ENTRY']} files to one entry")
    hard_cap = max(cfg["MEDIA_LIMITS"].values())
    items, total = [], used_bytes
    for n, f in enumerate(files, 1):
        data = f.read(hard_cap + 1)
        if not data:
            raise ValidationError(f"'{f.filename}' is empty")
        found = sniff(data[:32], f.mimetype or "")
        if not found:
            raise ValidationError(f"'{f.filename}' isn't a supported file. You can add {ALLOWED_DESCRIPTION}.")
        mime, kind = found
        limit = cfg["MEDIA_LIMITS"][kind]
        if len(data) > limit:
            raise ValidationError(f"'{f.filename}' is too big. {kind.capitalize()}s can be up to {limit // (1024 * 1024)} MB.")
        total += len(data)
        if total > cfg["MEDIA_USER_QUOTA"]:
            raise ValidationError(f"Your storage is full ({cfg['MEDIA_USER_QUOTA'] // (1024 * 1024)} MB). "
                                  "Download your evidence pack, then delete older files to make space.")
        name = secure_filename(f.filename or "")[:100] or f"{kind}-{n}"
        items.append({"data": data, "mime": mime, "kind": kind, "name": name})
    return items


def write_encrypted(vault, uid: int, data: bytes) -> str:
    stored_name = secrets.token_hex(16) + ".bin"
    path = os.path.join(media_dir(), stored_name)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(MAGIC + vault.encrypt_bytes(data, _ctx(uid, stored_name)))
    os.replace(tmp, path)  # atomic: never a half-written evidence file
    return stored_name


def read_decrypted(vault, uid: int, stored_name: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{32}\.bin", stored_name):
        raise DecryptionError("bad stored name")
    with open(os.path.join(media_dir(), stored_name), "rb") as fh:
        blob = fh.read()
    if not blob.startswith(MAGIC):
        raise DecryptionError("not an encrypted Dudu file")
    return vault.decrypt_bytes(blob[len(MAGIC):], _ctx(uid, stored_name))


def delete_files(stored_names):
    for name in stored_names:
        if re.fullmatch(r"[0-9a-f]{32}\.bin", name or ""):
            try:
                os.remove(os.path.join(media_dir(), name))
            except FileNotFoundError:
                pass


def remove_orphans(known_names: set[str]) -> int:
    """Delete stored files that no database row points to (e.g. after a crash)."""
    removed = 0
    for name in os.listdir(media_dir()):
        if (name.endswith(".bin") and name not in known_names) or name.endswith(".tmp"):
            os.remove(os.path.join(media_dir(), name))
            removed += 1
    return removed
