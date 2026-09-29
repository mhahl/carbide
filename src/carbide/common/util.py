"""Small shared helpers: ids, time, hashing, base64."""
import base64
import datetime
import errno
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


class BindError(Exception):
    """Startup failure: a listener socket could not be bound.

    Entrypoints catch this and print it as a one-line error instead of
    a traceback, so the message must be self-contained and actionable.
    """


def _bind_errno(exc: BaseException):
    """Best-effort errno: asyncio's aggregate bind error drops it, so
    also look through the chain (and the raw message) for the cause."""
    seen = set()
    err = exc
    while err is not None and id(err) not in seen:
        seen.add(id(err))
        if isinstance(err, OSError) and err.errno:
            return err.errno
        err = err.__cause__ or err.__context__
    return 0


def bind_failure(what: str, addr: str, port: int,
                 exc: OSError) -> BindError:
    """Build an actionable BindError for a listener bind failure.

    ``what`` names the listener ("sensor SSH listener"); the hint covers
    the three usual causes: port taken, address not local (typically a
    public IP used inside a container), or a privileged port.
    """
    err = _bind_errno(exc)
    msg = str(exc).splitlines()
    detail = msg[-1].strip() if msg else ""
    lowered = detail.lower()
    if err == errno.EADDRINUSE or "already in use" in lowered:
        hint = (f"port {port} is already in use — stop the process "
                f"that owns it or pick another port")
        if int(port) == 22:
            hint += " (on sensor hosts this is usually the host's own sshd)"
    elif err == errno.EADDRNOTAVAIL or "assign requested address" in lowered:
        hint = (f"{addr} is not an address on this machine — inside a "
                f"container bind 0.0.0.0 and map the public address via "
                f"the compose ports: line")
    elif err in (errno.EACCES, errno.EPERM) or "permission denied" in lowered:
        hint = (f"permission denied binding port {port} — ports below "
                f"1024 need root (or a higher port)")
    elif "could not bind on any address" in lowered:
        # asyncio's aggregate error lost the errno; name both suspects.
        hint = (f"check {addr} exists on this machine (inside a container "
                f"bind 0.0.0.0) and that port {port} is free")
    elif detail:
        hint = detail
    else:
        hint = errno.errorcode.get(err, f"errno {err}")
    return BindError(f"cannot bind {what} on {addr}:{port}: {hint}")
