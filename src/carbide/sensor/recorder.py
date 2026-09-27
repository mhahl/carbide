"""Per-session recorder: turns everything observable on an attacker SSH
connection into spool records for store-and-forward delivery.
"""
from ..common import protocol
from ..common.protocol import CHUNK_BYTES, iter_blob_chunks
from ..common.util import b64e, new_id, sha256_hex, utcnow_iso
from .spool import Spool


class Recorder:
    def __init__(self, spool: Spool, sensor_id: str, session_id: str,
                 wake=None):
        self._spool = spool
        self._sensor_id = sensor_id
        self.session_id = session_id
        self._wake = wake or (lambda: None)

    def _emit(self, kind: str, **fields) -> str:
        record = {
            "record_id": new_id(),
            "kind": kind,
            "sensor_id": self._sensor_id,
            "session_id": self.session_id,
            "at": utcnow_iso(),
        }
        record.update(fields)
        _slot, record_id = self._spool.append(record)
        self._wake()
        return record_id

    # -- lifecycle -----------------------------------------------------
    def session_start(self, attacker_ip: str, username: str) -> str:
        return self._emit(protocol.KIND_SESSION_START,
                          attacker_ip=attacker_ip, username=username)

    def session_container(self, container_id: str, fresh: bool) -> str:
        return self._emit(protocol.KIND_SESSION_CONTAINER,
                          container_id=container_id, fresh=fresh)

    def session_end(self, reason: str) -> str:
        return self._emit(protocol.KIND_SESSION_END, reason=reason)

    # -- auth ----------------------------------------------------------
    def auth_attempt(self, username: str, password: str, accepted: bool,
                     matched_list: bool) -> str:
        return self._emit(protocol.KIND_AUTH_ATTEMPT, username=username,
                          password=password, accepted=accepted,
                          matched_list=matched_list)

    # -- bytes ---------------------------------------------------------
    def transcript(self, channel: str, direction: str, stream: str,
                   data: bytes) -> list[str]:
        """direction: ``in`` (attacker->container) or ``out``."""
        ids = []
        for seq, _last, part in iter_blob_chunks(data, CHUNK_BYTES):
            ids.append(self._emit(protocol.KIND_TRANSCRIPT, channel=channel,
                                  direction=direction, stream=stream,
                                  seq=seq, data_b64=b64e(part)))
        return ids

    def evidence(self, name: str, data: bytes) -> str:
        """Store a copied file; returns its blob sha256."""
        sha = sha256_hex(data)
        self._emit(protocol.KIND_BLOB_META, blob_sha=sha, name=name,
                   size=len(data))
        for seq, last, part in iter_blob_chunks(data, CHUNK_BYTES):
            self._emit(protocol.KIND_BLOB_CHUNK, blob_sha=sha, name=name,
                       seq=seq, last=last, data_b64=b64e(part))
        return sha
