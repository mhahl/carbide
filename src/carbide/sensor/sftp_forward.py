"""SFTP subsystem forwarding: attacker SFTP requests execute against the
container over a client SFTP session, with copied file bytes saved as evidence
and every operation logged.
"""
import errno
import logging
import os

import asyncssh
from asyncssh.constants import (
    FXF_APPEND,
    FXF_EXCL,
    FXF_READ,
    FXF_WRITE,
)

log = logging.getLogger("carbide.sensor.sftp")


def mode_for_pflags(pflags: int) -> str:
    if pflags & FXF_EXCL:
        return "x"
    read = bool(pflags & FXF_READ)
    write = bool(pflags & FXF_WRITE)
    if read and write:
        return "r+"
    if write:
        if pflags & FXF_APPEND:
            return "a"
        return "w"
    return "r"


class _EvidenceSink:
    """Reassembles a byte stream; zero-fills gaps if writes were sparse."""

    def __init__(self, cap: int = 256 * 1024 * 1024):
        self._segs: list[tuple[int, bytes]] = []
        self._cap = cap
        self.truncated = False

    def add(self, offset: int, data: bytes):
        if self.truncated:
            return
        total = sum(len(d) for _, d in self._segs) + len(data)
        if total > self._cap:
            self.truncated = True
            return
        self._segs.append((offset, data))

    def result(self) -> bytes:
        if not self._segs:
            return b""
        end = max(off + len(d) for off, d in self._segs)
        buf = bytearray(end)
        for off, data in self._segs:
            buf[off:off + len(data)] = data
        return bytes(buf)


class _ForwardedFile:
    def __init__(self, client_file, path: str, uploader: bool,
                 evidence_cb, ops_cb):
        self._cf = client_file
        self._path = path
        self._uploader = uploader
        self._evidence_cb = evidence_cb
        self._ops_cb = ops_cb
        self._up = _EvidenceSink()
        self._down = _EvidenceSink()
        self._pos = 0

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        # Only used by the sparse-ranges probe; report the whole range
        # as data (correct, just without sparseness savings).
        if whence == os.SEEK_DATA:
            return offset
        if whence == os.SEEK_HOLE:
            return 2 ** 62  # caller clamps to the requested limit
        if whence == os.SEEK_SET:
            self._pos = offset
        elif whence == os.SEEK_CUR:
            self._pos += offset
        else:
            raise OSError(errno.EINVAL, "unsupported whence")
        return self._pos

    def tell(self) -> int:
        return self._pos

    async def read(self, size: int, offset: int) -> bytes:
        data = await self._cf.read(size, offset)
        if data:
            self._down.add(offset, bytes(data))
        return data

    async def write(self, data: bytes, offset: int) -> int:
        count = await self._cf.write(data, offset)
        self._up.add(offset, bytes(data[:count]))
        return count

    async def close(self):
        try:
            up = self._up.result()
            down = self._down.result()
            if up:
                self._evidence_cb(f"sftp-upload:{self._path}", up)
                self._ops_cb(f"upload {self._path} {len(up)} bytes")
            if down:
                self._evidence_cb(f"sftp-download:{self._path}", down)
                self._ops_cb(f"download {self._path} {len(down)} bytes")
        finally:
            await self._cf.close()


class ForwardingSFTPServer(asyncssh.SFTPServer):
    """asyncssh SFTPServer that executes everything on the container."""

    def __init__(self, chan, sftp_client, evidence_cb, ops_cb):
        super().__init__(chan)
        self._client = sftp_client
        self._evidence_cb = evidence_cb
        self._ops_cb = ops_cb

    @staticmethod
    def _name(path: bytes) -> str:
        return path.decode("utf-8", "replace")

    async def open(self, path: bytes, pflags: int, attrs):
        mode = mode_for_pflags(pflags)
        self._ops_cb(f"open {self._name(path)} mode={mode}")
        client_file = await self._client.open(
            path, pflags, attrs, encoding=None)
        return _ForwardedFile(client_file, self._name(path),
                              bool(pflags & FXF_WRITE),
                              self._evidence_cb, self._ops_cb)

    async def close(self, file_obj: _ForwardedFile):
        await file_obj.close()

    async def read(self, file_obj: _ForwardedFile, offset: int, size: int):
        return await file_obj.read(size, offset)

    async def write(self, file_obj: _ForwardedFile, offset: int, data: bytes):
        return await file_obj.write(data, offset)

    async def lstat(self, path: bytes):
        self._ops_cb(f"lstat {self._name(path)}")
        return await self._client.lstat(path)

    async def stat(self, path: bytes):
        self._ops_cb(f"stat {self._name(path)}")
        return await self._client.stat(path)

    async def fstat(self, file_obj: _ForwardedFile):
        return await self._client.lstat(
            file_obj._path.encode("utf-8", "replace"))

    async def scandir(self, path: bytes):
        self._ops_cb(f"listdir {self._name(path)}")
        async for name in self._client.scandir(path):
            yield name

    async def remove(self, path: bytes):
        self._ops_cb(f"remove {self._name(path)}")
        await self._client.remove(path)

    async def mkdir(self, path: bytes, attrs):
        self._ops_cb(f"mkdir {self._name(path)}")
        await self._client.mkdir(path)

    async def rmdir(self, path: bytes):
        self._ops_cb(f"rmdir {self._name(path)}")
        await self._client.rmdir(path)

    async def realpath(self, path: bytes):
        return await self._client.realpath(path)

    async def rename(self, oldpath: bytes, newpath: bytes):
        self._ops_cb(f"rename {self._name(oldpath)} -> {self._name(newpath)}")
        await self._client.rename(oldpath, newpath)

    async def readlink(self, path: bytes):
        self._ops_cb(f"readlink {self._name(path)}")
        return await self._client.readlink(path)
