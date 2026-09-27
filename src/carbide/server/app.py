"""carbide-server: API, affinity pool, forensics, eviction, Squid ingest."""
import asyncio
import logging

from ..common.blobstore import BlobStore
from .api import ServerAPI
from .db import Database
from .eviction import EvictionJob
from .forensics import Forensics
from .podman_wrap import PodmanWrapper
from .pool import Pool
from .squid import SquidTailer

log = logging.getLogger("carbide.server")


class ServerApp:
    def __init__(self, cfg, db=None, podman=None):
        self.cfg = cfg
        scfg = cfg.section("server")
        self.db = db or Database(scfg["db_dsn"])
        self.blobs = BlobStore(scfg["blob_dir"],
                               cfg.get("quotas.blob_max_bytes",
                                       10 * 1024**3))
        self.podman = podman or PodmanWrapper(
            cfg.get("podman.socket"))
        self.pool = Pool(self.podman, self.db, cfg)
        self.forensics = Forensics(self.pool, self.podman, self.db,
                                   self.blobs, cfg)
        self.eviction = EvictionJob(self.pool, self.podman, self.db,
                                    self.forensics, cfg)
        self.api = ServerAPI(self.db, self.pool, self.forensics,
                             self.blobs, cfg)
        if cfg.get("squid.enabled", True):
            self.squid = SquidTailer(self.db, cfg.get("squid.log_path"))
        else:
            self.squid = None

    async def run(self):
        await self.db.connect()
        await self.pool.start()
        tasks = [
            asyncio.create_task(self.api.run(), name="api"),
            asyncio.create_task(self.eviction.run_forever(),
                                name="eviction"),
        ]
        if self.squid is not None:
            tasks.append(asyncio.create_task(self.squid.run_forever(),
                                             name="squid"))
        log.info("carbide-server up")
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            # Wait for the children (the API drains its handlers first) so
            # nothing touches the database after it is closed.
            await asyncio.gather(*tasks, return_exceptions=True)
            if self.squid is not None:
                self.squid.stop()
            self.podman.close()
            await self.db.close()
