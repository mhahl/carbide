"""Small shared helpers: ids, time, hashing, base64."""
import base64
import datetime
import hashlib
import uuid


def utcnow_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))
