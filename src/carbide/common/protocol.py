"""Sensor<->server protocol: JSON-lines envelopes, records, blob chunks.

Transport: plain TCP (link security is the deployment's VPN). Every message is
one JSON object per line. Requests carry ``id``; responses carry
``{"type": "reply", "in_reply_to": id, "ok": bool}``.
Evidence records carry stable ``record_id`` values so forwarding is idempotent:
the server applies each record at most once.
"""


def new_reply(request_id: str, ok: bool = True, **fields) -> dict:
    reply = {"type": "reply", "in_reply_to": request_id, "ok": ok}
    reply.update(fields)
    return reply

import hashlib
import hmac
import json

from .util import new_id

CHUNK_BYTES = 32 * 1024

# record kinds (sensor -> server, inside "record" messages)
KIND_SESSION_START = "session_start"
KIND_SESSION_END = "session_end"
KIND_SESSION_CONTAINER = "session_container"
KIND_AUTH_ATTEMPT = "auth_attempt"
KIND_TRANSCRIPT = "transcript"
KIND_BLOB_META = "blob_meta"
KIND_BLOB_CHUNK = "blob_chunk"


def new_envelope(msg_type: str, **fields) -> dict:
    env = {"id": new_id(), "type": msg_type}
    env.update(fields)
    return env


def encode(msg: dict) -> bytes:
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")


def decode(line: bytes) -> dict:
    try:
        msg = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError(f"bad frame: {exc}")
    if not isinstance(msg, dict) or "type" not in msg:
        raise ProtocolError("frame must be an object with a type")
    return msg


class ProtocolError(Exception):
    pass


def tokens_equal(provided: str, expected: str) -> bool:
    return hmac.compare_digest(provided.encode(), expected.encode())


def iter_blob_chunks(data: bytes, chunk_size: int = CHUNK_BYTES):
    """Yield (seq, last, chunk) tuples for base64-safe transport upstream."""
    if not data:
        yield 0, True, b""
        return
    total = (len(data) + chunk_size - 1) // chunk_size
    for seq in range(total):
        part = data[seq * chunk_size:(seq + 1) * chunk_size]
        yield seq, seq == total - 1, part


class BlobReassembler:
    """Collects chunks keyed by blob sha256; verifies hash on completion."""

    def __init__(self):
        self._parts: dict[str, dict[int, bytes]] = {}
        self._done: dict[str, bool] = {}

    def discard(self, blob_sha: str):
        self._parts.pop(blob_sha, None)
        self._done.pop(blob_sha, None)

    def add(self, blob_sha: str, seq: int, last: bool, data: bytes):
        parts = self._parts.setdefault(blob_sha, {})
        if seq not in parts:
            parts[seq] = data
        if last:
            self._done[blob_sha] = True
        if self._done.get(blob_sha):
            seqs = sorted(parts)
            if seqs == list(range(len(seqs))):
                blob = b"".join(parts[i] for i in seqs)
                if hashlib.sha256(blob).hexdigest() != blob_sha:
                    raise ProtocolError("blob hash mismatch for "
                                        f"{blob_sha[:16]}...")
                del self._parts[blob_sha]
                del self._done[blob_sha]
                return blob
        return None
