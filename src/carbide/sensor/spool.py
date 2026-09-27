"""Durable outbox spool: every evidence record is fsync'd to disk before it
is forwarded, so a crash or VPN outage loses nothing. The server applies each
``record_id`` at most once, so redelivery after a crash is safe.
"""
import json
import os

from ..common.util import new_id


class Spool:
    def __init__(self, path: str):
        self._dir = os.path.abspath(path)
        os.makedirs(self._dir, exist_ok=True)
        self._seq = 0
        for name in os.listdir(self._dir):
            head, _, _ = name.partition("-")
            if head.isdigit():
                self._seq = max(self._seq, int(head) + 1)

    def append(self, record: dict) -> tuple[str, str]:
        """Persist a record; returns (slot_name, record_id)."""
        record = dict(record)
        record_id = record.get("record_id") or new_id()
        record["record_id"] = record_id
        slot = f"{self._seq:010d}-{record_id}.json"
        self._seq += 1
        tmp = os.path.join(self._dir, slot + ".tmp")
        with open(tmp, "w") as fh:
            json.dump(record, fh, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, os.path.join(self._dir, slot))
        try:
            dirfd = os.open(self._dir, os.O_DIRECTORY)
        except OSError:
            return slot, record_id
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        return slot, record_id

    def pending(self) -> list[tuple[str, dict]]:
        out = []
        for name in sorted(os.listdir(self._dir)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self._dir, name)) as fh:
                    out.append((name, json.load(fh)))
            except (OSError, ValueError):
                continue
        return out

    def ack(self, slot: str) -> None:
        try:
            os.unlink(os.path.join(self._dir, slot))
        except FileNotFoundError:
            pass

    def __len__(self) -> int:
        return len(self.pending())
