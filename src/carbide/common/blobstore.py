"""Blob store: narrow put/get/delete interface, filesystem implementation.

Blobs are content-addressed (sha256 of bytes) and written atomically, which
gives dedupe across sessions/sensors plus an integrity check at read time.
An S3-compatible backend can implement the same interface later (D10).
"""
import os
from dataclasses import dataclass

from .util import sha256_hex


class QuotaExceeded(Exception):
    pass


@dataclass(frozen=True)
class BlobRef:
    sha256: str
    path: str
    size: int


class BlobStore:
    def __init__(self, root: str, max_bytes: int):
        self._root = os.path.abspath(root)
        self._max_bytes = max_bytes
        os.makedirs(self._root, exist_ok=True)
        self._total = self._scan_size()

    @property
    def root(self) -> str:
        return self._root

    @property
    def total_bytes(self) -> int:
        return self._total

    def _scan_size(self) -> int:
        total = 0
        for dirpath, _dirnames, filenames in os.walk(self._root):
            for name in filenames:
                if name.endswith(".tmp"):
                    continue
                try:
                    total += os.path.getsize(os.path.join(dirpath, name))
                except OSError:
                    continue
        return total

    def path_for(self, sha: str) -> str:
        return os.path.join(self._root, sha[:2], sha)

    def exists(self, sha: str) -> bool:
        return os.path.isfile(self.path_for(sha))

    def put_bytes(self, data: bytes) -> BlobRef:
        sha = sha256_hex(data)
        dest = self.path_for(sha)
        if os.path.isfile(dest):
            return BlobRef(sha, dest, len(data))
        if self._total + len(data) > self._max_bytes:
            raise QuotaExceeded(
                f"blob store quota exceeded: {self._total}+{len(data)} > "
                f"{self._max_bytes}")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dest)
        self._total += len(data)
        return BlobRef(sha, dest, len(data))

    def get_bytes(self, sha: str) -> bytes:
        with open(self.path_for(sha), "rb") as fh:
            data = fh.read()
        if sha256_hex(data) != sha:
            raise ValueError(f"blob integrity failure for {sha[:16]}...")
        return data

    def delete(self, sha: str) -> bool:
        try:
            size = os.path.getsize(self.path_for(sha))
            os.unlink(self.path_for(sha))
        except FileNotFoundError:
            return False
        self._total = max(0, self._total - size)
        return True
