"""Synchronous Podman wrapper (always called from an executor) plus the
narrow container-surface the rest of carbide-server programs against.
"""
import io
import logging
import tarfile

log = logging.getLogger("carbide.server.podman")


class PodmanError(Exception):
    pass


class IsDirError(PodmanError):
    """Raised by get_file when the path is a directory."""


class PodmanWrapper:
    """Thin sync wrapper over podman-py. Raises PodmanError on failures."""

    def __init__(self, socket_url: str):
        self._url = socket_url
        self._client = None

    def connect(self):
        from podman import PodmanClient
        self._client = PodmanClient(base_url=self._url)
        try:
            self._client.ping()
        except Exception as exc:
            raise PodmanError(f"podman ping failed: {exc}")
        log.info("connected to podman at %s", self._url)

    def close(self):
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            log.debug("podman connection closed")

    def _wrap(self, op, *args, **kwargs):
        try:
            return op(*args, **kwargs)
        except Exception as exc:
            raise PodmanError(f"{op.__name__} failed: {exc}")

    # -- lifecycle ------------------------------------------------------
    def ensure_network(self, name: str):
        if not name:
            return
        exists = self._wrap(self._client.networks.exists, name)
        if not exists:
            self._wrap(self._client.networks.create, name)
            log.info("created podman network %s", name)
        else:
            log.debug("podman network %s present", name)

    def create_container(self, name: str, image: str, user: str,
                         host_port: int, network: str, environment: dict,
                         memory_mb: int, pids_limit: int) -> str:
        kwargs: dict = {
            "name": name,
            "ports": {22: host_port},
            "environment": environment,
            "mem_limit": f"{memory_mb}m",
            "pids_limit": pids_limit,
            "labels": {"carbide": "affinity"},
            "detach": True,
        }
        if network:
            kwargs["network"] = network
        container = self._wrap(self._client.containers.create, image,
                               **kwargs)
        log.debug("created container %s (%s) image=%s port=%s",
                  name, container.id[:12], image, host_port)
        return container.id

    def start(self, cid: str):
        log.debug("starting container %s", cid[:12])
        self._wrap(self._client.containers.get(cid).start)

    def stop(self, cid: str, timeout: int = 10):
        try:
            container = self._client.containers.get(cid)
        except Exception:
            log.debug("stop %s: already gone", cid[:12])
            return
        log.debug("stopping container %s", cid[:12])
        try:
            container.stop(timeout=timeout)
        except Exception as exc:
            raise PodmanError(f"stop failed: {exc}")

    def remove(self, cid: str):
        try:
            container = self._client.containers.get(cid)
        except Exception:
            log.debug("remove %s: already gone", cid[:12])
            return
        log.debug("removing container %s", cid[:12])
        self._wrap(container.remove, force=True)

    def exists(self, cid: str) -> bool:
        try:
            self._client.containers.get(cid)
            return True
        except Exception:
            return False

    def status(self, cid: str) -> str:
        try:
            container = self._client.containers.get(cid)
            container.reload()
            return container.status
        except Exception:
            return "missing"

    def inspect(self, cid: str) -> dict:
        return self._wrap(self._client.containers.get(cid).inspect)

    def container_ip(self, cid: str) -> str:
        try:
            info = self.inspect(cid)
            nets = info.get("NetworkSettings", {}).get("Networks", {})
            for net in nets.values():
                if net.get("IPAddress"):
                    return net["IPAddress"]
            return info.get("NetworkSettings", {}).get("IPAddress", "")
        except PodmanError:
            return ""

    def list_carbide(self) -> list:
        found = []
        containers = self._wrap(self._client.containers.list, all=True)
        for container in containers:
            try:
                if container.labels.get("carbide"):
                    found.append(container)
            except Exception:
                continue
        return found

    # -- forensics --------------------------------------------------------
    def diff(self, cid: str) -> list:
        log.debug("diff container %s", cid[:12])
        return self._wrap(self._client.containers.get(cid).diff)

    def get_file(self, cid: str, path: str) -> tuple[bytes, dict]:
        """Returns (bytes, stat). Raises PodmanError (incl. IsDir)."""
        log.debug("get file %s from %s", path, cid[:12])
        container = self._client.containers.get(cid)
        try:
            stream, stat = container.get_archive(path)
        except Exception as exc:
            raise PodmanError(f"get_archive failed: {exc}")
        chunks = []
        try:
            for piece in stream:
                chunks.append(piece)
        except Exception as exc:
            raise PodmanError(f"archive read failed: {exc}")
        if stat.get("isDir"):
            raise IsDirError(f"{path} is a directory")
        data = io.BytesIO(b"".join(chunks))
        try:
            with tarfile.open(fileobj=data) as tar:
                members = [m for m in tar.getmembers() if m.isfile()]
                if not members:
                    raise PodmanError(f"{path}: no file in archive")
                extracted = tar.extractfile(members[0])
                return extracted.read(), stat
        except tarfile.TarError as exc:
            raise PodmanError(f"tar decode failed: {exc}")

    def export_to(self, cid: str, dest_path: str):
        log.debug("exporting container %s", cid[:12])
        container = self._client.containers.get(cid)
        try:
            with open(dest_path, "wb") as fh:
                for piece in container.export():
                    fh.write(piece)
        except Exception as exc:
            raise PodmanError(f"export failed: {exc}")

    def commit(self, cid: str, image: str) -> str:
        log.debug("committing container %s as %s", cid[:12], image)
        container = self._client.containers.get(cid)
        repo, _, tag = image.partition(":")
        try:
            img = container.commit(repository=repo or None, tag=tag or None)
        except Exception as exc:
            raise PodmanError(f"commit failed: {exc}")
        return img.id

    def remove_image(self, image: str):
        try:
            self._client.images.remove(image, force=True)
        except Exception as exc:
            log.warning("remove image %s failed: %s", image, exc)
        else:
            log.debug("removed image %s", image)
