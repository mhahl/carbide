"""VirusTotal v3 file + URL verdicts: lookup-first, submit-on-miss, quota pacing.

Public tier allows 4 requests/minute and 500/day, so every HTTP request
passes the per-minute pacer and the persisted daily quota claim.
Anything unknown is submitted once and then polled by analysis id —
pending rows resume polling on later passes, never re-submit.
"""
import asyncio
import base64
import datetime
import json
import logging
import time

import aiohttp

log = logging.getLogger("carbide.server.vt")

BASE_URL = "https://www.virustotal.com/api/v3"
VT_KEY_SETTING = "virustotal.api_key"
_MAX_DETECTIONS = 50
_MAX_RETRIES = 3


class VTError(Exception):
    pass


class VTAuthError(VTError):
    """401: bad api_key — the worker stops the pass."""


class VTQuotaExceeded(VTError):
    """Local daily cap reached — the worker stops the pass."""


def _verdict(malicious: int, suspicious: int, harmless: int,
             undetected: int) -> str:
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    if harmless + undetected > 0:
        return "clean"
    return "unknown"


def url_id(url: str) -> str:
    """VT url id: base64url of the URL without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode(
        "ascii").rstrip("=")


def _summary(stats: dict, results: dict, ref: str, extra: dict,
             permalink: str = "") -> dict:
    stats = stats or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    detections = []
    for engine in sorted(results or {}):
        result = results[engine] or {}
        if result.get("category") in ("malicious", "suspicious"):
            detections.append({
                "engine": engine,
                "category": result.get("category", ""),
                "result": result.get("result", ""),
            })
            if len(detections) >= _MAX_DETECTIONS:
                break
    summary = {
        "status": _verdict(malicious, suspicious, harmless, undetected),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "permalink": permalink or
        f"https://www.virustotal.com/gui/file/{ref}",
        "detections": detections,
    }
    summary.update(extra)
    return summary


def summarize_file(body: dict, sha: str) -> dict:
    """Normalize a GET /files/{sha} response body to a verdict summary."""
    attrs = (body.get("data") or {}).get("attributes") or {}
    return _summary(attrs.get("last_analysis_stats"),
                    attrs.get("last_analysis_results"), sha, {
                        "names": list(attrs.get("names") or [])[:10],
                        "size": int(attrs.get("size") or 0),
                    })


def summarize_url(body: dict, url: str) -> dict:
    """Normalize a GET /urls/{id} response body to a verdict summary."""
    attrs = (body.get("data") or {}).get("attributes") or {}
    return _summary(attrs.get("last_analysis_stats"),
                    attrs.get("last_analysis_results"), url, {
                        "url": url,
                    },
                    permalink="https://www.virustotal.com/gui/url/"
                    + url_id(url))


def summarize_analysis(attrs: dict, sha: str, permalink: str = "") -> dict:
    """Normalize a completed analysis attributes object to a summary."""
    return _summary(attrs.get("stats"), attrs.get("results"), sha, {},
                    permalink=permalink)


class AiohttpTransport:
    """Real VT HTTP transport; tests inject a fake with the same shape."""

    def __init__(self, api_key: str, base_url: str = BASE_URL,
                 timeout_s: float = 30.0):
        self._key = api_key
        self._base = base_url.rstrip("/")
        self._timeout = aiohttp.ClientTimeout(total=timeout_s)

    async def get(self, path: str):
        async with aiohttp.ClientSession(timeout=self._timeout) as sess:
            async with sess.get(self._base + path,
                                headers={"x-apikey": self._key}) as resp:
                return resp.status, await self._json(resp), resp.headers

    async def post_file(self, path: str, data: bytes, filename: str):
        form = aiohttp.FormData()
        form.add_field("file", data, filename=filename,
                       content_type="application/octet-stream")
        async with aiohttp.ClientSession(timeout=self._timeout) as sess:
            async with sess.post(self._base + path, data=form,
                                 headers={"x-apikey": self._key}) as resp:
                return resp.status, await self._json(resp), resp.headers

    async def post_form(self, path: str, fields: dict):
        form = aiohttp.FormData()
        for key, value in fields.items():
            form.add_field(key, value)
        async with aiohttp.ClientSession(timeout=self._timeout) as sess:
            async with sess.post(self._base + path, data=form,
                                 headers={"x-apikey": self._key}) as resp:
                return resp.status, await self._json(resp), resp.headers

    @staticmethod
    async def _json(resp):
        try:
            return await resp.json()
        except Exception:
            return {}


class VTClient:
    def __init__(self, api_key: str, requests_per_minute: int = 4,
                 quota_claim=None, transport=None):
        """quota_claim: async () -> bool, one VT request per True."""
        self._interval = 60.0 / max(1, requests_per_minute)
        self._claim = quota_claim
        self._transport = transport or AiohttpTransport(api_key)
        self._lock = asyncio.Lock()
        self._next_at = 0.0

    async def _pace(self):
        async with self._lock:
            delay = self._next_at - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next_at = time.monotonic() + self._interval

    async def _call(self, method: str, *args):
        last: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            if self._claim is not None and not await self._claim():
                raise VTQuotaExceeded("daily VirusTotal quota exhausted")
            await self._pace()
            try:
                if method == "GET":
                    status, body, headers = await self._transport.get(*args)
                elif method == "POST":
                    status, body, headers = await self._transport.post_file(
                        *args)
                else:
                    status, body, headers = await self._transport.post_form(
                        *args)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # transport error: back off, retry
                last = exc
                await asyncio.sleep(min(2 ** attempt, 30))
                continue
            if status == 429 and attempt < _MAX_RETRIES:
                try:
                    wait = float(headers.get("Retry-After", "15"))
                except (TypeError, ValueError):
                    wait = 15.0
                await asyncio.sleep(min(max(wait, 1.0), 120.0))
                continue
            if status >= 500 and attempt < _MAX_RETRIES:
                await asyncio.sleep(min(2 ** attempt, 30))
                continue
            return status, body or {}, headers
        raise VTError(f"VirusTotal request failed: {last}")

    async def lookup(self, sha: str):
        """File verdict summary, or None when VT never saw the hash."""
        status, body, _ = await self._call("GET", f"/files/{sha}")
        if status == 404:
            return None
        if status == 401:
            raise VTAuthError("VirusTotal rejected the api_key (401)")
        if status != 200:
            raise VTError(f"lookup {sha[:12]}: http {status}")
        try:
            return summarize_file(body, sha)
        except (KeyError, TypeError, ValueError) as exc:
            raise VTError(f"lookup {sha[:12]}: bad response ({exc})")

    async def upload(self, data: bytes, filename: str) -> str:
        """Submit bytes; returns the analysis id for polling."""
        status, body, _ = await self._call(
            "POST", "/files", data, filename)
        if status == 401:
            raise VTAuthError("VirusTotal rejected the api_key (401)")
        if status != 200:
            raise VTError(f"upload {filename}: http {status}")
        try:
            return body["data"]["id"]
        except (KeyError, TypeError):
            raise VTError(f"upload {filename}: bad response")

    async def lookup_url(self, url: str):
        """URL verdict summary, or None when VT never saw the URL."""
        status, body, _ = await self._call(
            "GET", f"/urls/{url_id(url)}")
        if status == 404:
            return None
        if status == 401:
            raise VTAuthError("VirusTotal rejected the api_key (401)")
        if status != 200:
            raise VTError(f"url lookup: http {status}")
        try:
            return summarize_url(body, url)
        except (KeyError, TypeError, ValueError) as exc:
            raise VTError(f"url lookup: bad response ({exc})")

    async def submit_url(self, url: str) -> str:
        """Submit a URL for analysis; returns the analysis id."""
        status, body, _ = await self._call(
            "FORM", "/urls", {"url": url})
        if status == 401:
            raise VTAuthError("VirusTotal rejected the api_key (401)")
        if status != 200:
            raise VTError(f"url submit: http {status}")
        try:
            return body["data"]["id"]
        except (KeyError, TypeError):
            raise VTError("url submit: bad response")

    async def poll_analysis(self, analysis_id: str, sha: str,
                            permalink: str = ""):
        """(completed, summary|None) for one queued analysis."""
        status, body, _ = await self._call(
            "GET", f"/analyses/{analysis_id}")
        if status == 401:
            raise VTAuthError("VirusTotal rejected the api_key (401)")
        if status == 404:
            raise VTError(f"analysis {analysis_id[:16]} expired")
        if status != 200:
            raise VTError(f"analysis {analysis_id[:16]}: http {status}")
        try:
            attrs = body["data"]["attributes"]
        except (KeyError, TypeError):
            raise VTError(f"analysis {analysis_id[:16]}: bad response")
        if attrs.get("status") != "completed":
            return False, None
        try:
            return True, summarize_analysis(attrs, sha,
                                            permalink=permalink)
        except (KeyError, TypeError, ValueError) as exc:
            raise VTError(f"analysis {analysis_id[:16]}: bad result ({exc})")


async def resolve_vt_key(db, cfg) -> str:
    """Effective API key: console setting first, file config fallback."""
    stored = await db.get_setting(VT_KEY_SETTING)
    if stored and stored.strip():
        return stored.strip()
    return cfg.section("virustotal")["api_key"] or ""


def build_client(cfg, db, transport=None, api_key=None) -> VTClient:
    """VTClient wired to config limits and the persisted daily quota."""
    vcfg = cfg.section("virustotal")
    cap = vcfg["daily_cap"]

    async def claim() -> bool:
        today = datetime.datetime.now(datetime.timezone.utc).date()
        return await db.claim_vt_quota(today, cap)

    return VTClient(api_key if api_key is not None else vcfg["api_key"],
                    requests_per_minute=vcfg["requests_per_minute"],
                    quota_claim=claim, transport=transport)


class VTQueue:
    """Drains unscanned blobs through VirusTotal, paced by quota.

    The API key resolves per pass (console setting, else file config),
    so a key saved in the console takes effect without a restart. With
    no key anywhere the pass is a quiet no-op (a warning when the file
    config claims enabled).
    """

    def __init__(self, db, blobs, cfg, client=None,
                 interval_s: float = 300.0, batch: int = 25):
        self._db = db
        self._blobs = blobs
        self._cfg = cfg
        self._client = client
        self._injected = client is not None
        self._key = None
        self._rescan_days = cfg.get("virustotal.rescan_after_days", 30)
        self._max_upload = cfg.get("virustotal.max_upload_bytes",
                                   32 * 1024 * 1024)
        self._interval = interval_s
        self._batch = batch

    async def run_forever(self):
        log.info("vt queue started (pass every %ss)", self._interval)
        while True:
            try:
                done = await self.run_once()
                log.debug("vt pass: %d files", done)
            except Exception as exc:
                log.warning("vt pass failed: %s", exc)
            await asyncio.sleep(self._interval)

    async def run_once(self, now=None) -> int:
        now = now or datetime.datetime.now(datetime.timezone.utc)
        if not self._injected:
            key = await resolve_vt_key(self._db, self._cfg)
            if not key:
                if self._cfg.get("virustotal.enabled", False):
                    log.warning("vt enabled but no api key set")
                else:
                    log.debug("vt idle: no api key")
                return 0
            if key != self._key:
                self._client = build_client(self._cfg, self._db,
                                            api_key=key)
                self._key = key
        cutoff = now - datetime.timedelta(days=self._rescan_days)
        done = 0
        for sha, size in await self._db.vt_candidates(self._batch, cutoff):
            try:
                await self._scan_one(sha, size)
            except VTQuotaExceeded:
                log.info("vt daily quota exhausted; stopping pass")
                return done
            except VTAuthError as exc:
                log.error("vt auth failed (bad api_key?): %s", exc)
                return done
            except VTError as exc:
                log.warning("vt scan %s failed: %s", sha[:12], exc)
                await self._db.save_vt_scan(sha, "error",
                                            error=str(exc)[:500])
            done += 1
        for url, analysis_id in await self._db.pending_vt_urls(
                self._batch):
            try:
                await self._poll_one_url(url, analysis_id)
            except VTQuotaExceeded:
                log.info("vt daily quota exhausted; stopping pass")
                return done
            except VTAuthError as exc:
                log.error("vt auth failed (bad api_key?): %s", exc)
                return done
            except VTError as exc:
                log.warning("vt url poll failed: %s", exc)
                await self._db.save_vt_url_scan(
                    url, "error", error=str(exc)[:500])
            done += 1
        return done

    async def _save_summary(self, sha: str, summary: dict):
        await self._db.save_vt_scan(
            sha, summary["status"], malicious=summary["malicious"],
            suspicious=summary["suspicious"], harmless=summary["harmless"],
            undetected=summary["undetected"],
            permalink=summary["permalink"],
            report_json=json.dumps(summary))

    async def _scan_one(self, sha: str, size: int):
        row = await self._db.get_vt_scan(sha)
        if row is not None and row["status"] == "pending" \
                and row["analysis_id"]:
            completed, summary = await self._client.poll_analysis(
                row["analysis_id"], sha)
            if completed:
                await self._save_summary(sha, summary)
                log.info("vt %s: %s", sha[:12], summary["status"])
            else:
                log.debug("vt %s: analysis still queued", sha[:12])
            return
        summary = await self._client.lookup(sha)
        if summary is not None:
            await self._save_summary(sha, summary)
            log.info("vt %s: known (%s)", sha[:12], summary["status"])
            return
        if size > self._max_upload:
            log.info("vt %s: %d bytes over upload cap, skipping",
                     sha[:12], size)
            await self._db.save_vt_scan(
                sha, "skipped",
                error=f"{size} bytes exceeds {self._max_upload} cap")
            return
        try:
            data = await asyncio.to_thread(self._blobs.get_bytes, sha)
        except (OSError, ValueError) as exc:
            await self._db.save_vt_scan(
                sha, "error", error=f"blob unreadable: {exc}"[:500])
            return
        analysis_id = await self._client.upload(data, sha[:16])
        await self._db.save_vt_scan(sha, "pending",
                                    analysis_id=analysis_id)
        log.info("vt %s: uploaded, polling next pass", sha[:12])

    async def scan_url(self, url: str) -> dict:
        """Lookup-or-submit one URL; returns the stored scan row.

        Raises VTAuthError/VTQuotaExceeded/VTError like _scan_one.
        """
        summary = await self._client.lookup_url(url)
        if summary is not None:
            await self._save_url_summary(url, summary)
            log.info("vt url %s: known (%s)", url[:60],
                     summary["status"])
        else:
            analysis_id = await self._client.submit_url(url)
            await self._db.save_vt_url_scan(url, "pending",
                                            analysis_id=analysis_id)
            log.info("vt url %s: submitted, polling next pass",
                     url[:60])
        return await self._db.get_vt_url_scan(url)

    async def _save_url_summary(self, url: str, summary: dict):
        await self._db.save_vt_url_scan(
            url, summary["status"], malicious=summary["malicious"],
            suspicious=summary["suspicious"], harmless=summary["harmless"],
            undetected=summary["undetected"],
            permalink=summary["permalink"],
            report_json=json.dumps(summary))

    async def _poll_one_url(self, url: str, analysis_id: str):
        permalink = ("https://www.virustotal.com/gui/url/" + url_id(url))
        completed, summary = await self._client.poll_analysis(
            analysis_id, url, permalink=permalink)
        if completed:
            await self._save_url_summary(url, summary)
            log.info("vt url %s: %s", url[:60], summary["status"])
        else:
            log.debug("vt url %s: analysis still queued", url[:60])
