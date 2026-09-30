"""carbide-server: API, affinity pool, forensics, eviction, Squid ingest."""
import asyncio
import logging

from ..common.blobstore import BlobStore
from .api import ServerAPI
from .bus import EventBus, LogRingHandler
from .db import Database
from .eviction import EvictionJob
from .forensics import Forensics
from .ipintel import IPIntel
from .podman_wrap import PodmanWrapper
from .pool import Pool
from .squid import SquidTailer
from .vt import VTQueue, build_client
from .web.webapp import WebConsole, create_app

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
        self.bus = EventBus()
        self.logring = LogRingHandler(self.bus)
        self.pool = Pool(self.podman, self.db, cfg, bus=self.bus)
        self.forensics = Forensics(self.pool, self.podman, self.db,
                                   self.blobs, cfg)
        self.eviction = EvictionJob(self.pool, self.podman, self.db,
                                    self.forensics, cfg)
        self.api = ServerAPI(self.db, self.pool, self.forensics,
                             self.blobs, cfg, bus=self.bus)
        if cfg.get("squid.enabled", True):
            self.squid = SquidTailer(self.db, cfg.get("squid.log_path"),
                                     bus=self.bus)
        else:
            self.squid = None
        if cfg.get("virustotal.enabled", False):
            self.vt = VTQueue(self.db, self.blobs,
                              build_client(cfg, self.db), cfg)
        else:
            self.vt = None
        if cfg.get("ipintel.enabled", True):
            self.ipintel = IPIntel(self.db, cfg)
        else:
            self.ipintel = None
        if cfg.get("web.enabled", True):
            self.web = WebConsole(create_app({
                "cfg": cfg, "db": self.db, "pool": self.pool,
                "pod": self.podman, "blobs": self.blobs,
                "api": self.api, "forensics": self.forensics,
                "eviction": self.eviction, "bus": self.bus,
                "logring": self.logring}), cfg)
        else:
            self.web = None

    async def run(self):
        log.info("starting carbide-server")
        logging.getLogger().addHandler(self.logring)
        await self.db.connect()
        log.info("postgres connected")
        await self.pool.start()
        tasks = [
            asyncio.create_task(self.api.run(), name="api"),
            asyncio.create_task(self.eviction.run_forever(),
                                name="eviction"),
        ]
        if self.squid is not None:
            tasks.append(asyncio.create_task(self.squid.run_forever(),
                                             name="squid"))
        else:
            log.info("squid ingest disabled")
        if self.vt is not None:
            tasks.append(asyncio.create_task(self.vt.run_forever(),
                                             name="vt"))
        else:
            log.info("vt queue disabled")
        if self.ipintel is not None:
            tasks.append(asyncio.create_task(self.ipintel.run_forever(),
                                             name="ipintel"))
        else:
            log.info("ipintel disabled")
        if self.web is not None:
            tasks.append(asyncio.create_task(self.web.run(), name="web"))
        else:
            log.info("web console disabled")
        log.info("carbide-server up")
        try:
            await asyncio.gather(*tasks)
        finally:
            log.info("shutting down")
            for task in tasks:
                task.cancel()
            # Wait for the children (the API drains its handlers first) so
            # nothing touches the database after it is closed.
            await asyncio.gather(*tasks, return_exceptions=True)
            if self.squid is not None:
                self.squid.stop()
            self.podman.close()
            await self.db.close()
            logging.getLogger().removeHandler(self.logring)
            log.info("carbide-server stopped")
