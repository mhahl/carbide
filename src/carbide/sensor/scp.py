"""Minimal SCP sink-protocol carver.

Observes one direction of an ``scp -t`` (upload) or ``scp -f`` (download)
channel from its first byte and carves complete files out of the stream:
``T`` (times), ``C`` (file), ``D`` (directory), ``E`` (end of directory).
Anything that does not parse is left available via :meth:`flush_raw` so the
caller can still store it as an opaque blob.
"""


class ScpCarver:
    def __init__(self, max_bytes: int = 100 * 1024 * 1024):
        self._buf = b""
        self._need = 0
        self._current: bytearray | None = None
        self._name = ""
        self._dirs: list[str] = []
        self._max_bytes = max_bytes
        self.done: list[tuple[str, bytes]] = []
        self.saw_dirs = False

    def _path(self, name: str) -> str:
        return "/".join(self._dirs + [name])

    def feed(self, data: bytes) -> list[tuple[str, bytes]]:
        self._buf += data
        if len(self._buf) > self._max_bytes + 1024 * 1024:
            raise ValueError("scp stream exceeded max_bytes without headers")
        while True:
            if self._current is not None:
                take = min(len(self._buf), self._need)
                self._current += self._buf[:take]
                self._buf = self._buf[take:]
                self._need -= take
                if self._need:
                    break
                self.done.append((self._name, bytes(self._current)))
                self._current = None
                continue
            nl = self._buf.find(b"\n")
            if nl < 0:
                break
            line = self._buf[:nl].decode("utf-8", "replace")
            self._buf = self._buf[nl + 1:]
            if not line:
                continue
            cmd, rest = line[0], line[1:]
            if cmd == "T":
                continue  # mtime/atime line precedes C; nothing to store
            elif cmd == "E":
                if self._dirs:
                    self._dirs.pop()
            elif cmd in ("C", "D"):
                parts = rest.split(" ", 2)
                if len(parts) != 3:
                    continue
                _mode, size_s, name = parts
                try:
                    size = int(size_s)
                except ValueError:
                    continue
                if size < 0 or size > self._max_bytes:
                    continue
                if cmd == "D":
                    self._dirs.append(name)
                    self.saw_dirs = True
                else:
                    self._name = self._path(name)
                    self._current = bytearray()
                    self._need = size
            else:
                # acks/errors (start with \x00/\x01/\x02) or garbage: skip line
                continue
        out, self.done = self.done, []
        return out

    def flush_raw(self) -> bytes:
        raw = self._buf
        self._buf = b""
        if self._current:
            raw = bytes(self._current) + raw
            self._current = None
            self._need = 0
        return raw
