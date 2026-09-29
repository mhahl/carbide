"""Forensic capture: normalize container diffs, fetch changed-file contents,
render easy-to-examine reports, manage per-session snapshots.
"""
import datetime
import difflib
import json
import logging
import re

from ..common.blobstore import QuotaExceeded
from .podman_wrap import IsDirError, PodmanError

log = logging.getLogger("carbide.server.forensics")

_INT_KINDS = {0: "changed", 1: "added", 2: "deleted"}
_STR_KINDS = {
    "a": "added", "added": "added", "add": "added",
    "d": "deleted", "deleted": "deleted", "delete": "deleted",
    "c": "changed", "changed": "changed", "modify": "changed",
    "modified": "changed",
}


def normalize_changes(raw: list) -> tuple[list[tuple[str, str]], list[str]]:
    """Normalize a container-changes payload to sorted (path, kind) rows.

    Accepts docker-style integer kinds (0 changed, 1 added, 2 deleted) and
    podman-style A/D/C strings. Unknown entries are labeled ``changed`` and
    reported in warnings rather than silently dropped.
    """
    rows: list[tuple[str, str]] = []
    warnings: list[str] = []
    for entry in raw or []:
        try:
            path = entry["Path"]
            kind = entry["Kind"]
        except (TypeError, KeyError):
            warnings.append(f"unparseable diff entry: {entry!r}")
            continue
        if isinstance(kind, int) and not isinstance(kind, bool):
            mapped = _INT_KINDS.get(kind)
        elif isinstance(kind, str):
            mapped = _STR_KINDS.get(kind.strip().lower())
        else:
            mapped = None
        if mapped is None:
            warnings.append(f"unknown change kind {kind!r} for {path}; "
                            "treated as changed")
            mapped = "changed"
        rows.append((str(path), mapped))
    rows.sort()
    return rows, warnings


def is_text(data: bytes) -> bool:
    return b"\x00" not in data[:8192]


def unified_diff_text(before: bytes | None, after: bytes | None,
                      path: str) -> str | None:
    if before is not None and not is_text(before):
        return None
    if after is not None and not is_text(after):
        return None
    a = before.decode("utf-8", "replace").splitlines() if before else []
    b = after.decode("utf-8", "replace").splitlines() if after is not None else []
    return "\n".join(difflib.unified_diff(
        a, b, fromfile=f"a{path}", tofile=f"b{path}"))


def _safe_tag(text: str) -> str:
    # Container image references must be lowercase; dots are dropped too so
    # a dotted IP can never parse as a registry domain.
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text).lower()[:64]


class Forensics:
    def __init__(self, pool, podman, db, blobstore, cfg):
        self._pool = pool
        self._pod = podman
        self._db = db
        self._blobs = blobstore
        self._max_file = cfg.get("forensics.max_file_bytes", 1024 * 1024)
        self._full_export = cfg.get("forensics.include_full_export", False)
        self._commit = cfg.get("affinity.commit_per_session", True)
        self._retention = cfg.get("affinity.snapshot_retention", 10)

    async def collect(self, *, sensor_id: str, attacker_ip: str,
                      session_id: str, container_id: str,
                      reason: str = "", final: bool = False) -> dict:
        """Run full capture for one session; returns a summary dict."""
        log.info("forensics starting: session=%s container=%s reason=%s",
                 session_id, container_id[:12], reason or "session end")
        at = datetime.datetime.now(datetime.timezone.utc)
        try:
            raw = await self._pool.run_sync(self._pod.diff, container_id)
        except Exception as exc:
            return await self._report_unavailable(
                session_id, sensor_id, attacker_ip, container_id, reason,
                f"diff failed: {exc}", at)
        try:
            rows, warnings = normalize_changes(raw)
        except TypeError as exc:
            return await self._report_unavailable(
                session_id, sensor_id, attacker_ip, container_id, reason,
                f"unusable diff payload: {exc}", at)
        log.debug("diff for %s: %d paths", session_id, len(rows))
        try:
            await self._db.add_diff_rows(session_id, rows)
        except Exception as exc:
            warnings.append(f"diff rows not stored: {exc}")
            log.warning("forensics %s: diff rows not stored: %s",
                        session_id, exc)
        changes = []
        try:
            for path, kind in rows:
                changes.append(await self._collect_path(
                    session_id, container_id, path, kind, warnings))
            if self._full_export or final:
                await self._collect_export(session_id, container_id, changes,
                                           warnings)
        except Exception as exc:
            # Never skip the report: partial capture plus a warning beats
            # a blank "No report yet." on the session page.
            warnings.append(f"capture interrupted: {exc}")
            log.warning("forensics %s: capture interrupted: %s",
                        session_id, exc)
        markdown, payload = self._render(
            session_id, sensor_id, attacker_ip, container_id, reason, at,
            changes, warnings)
        await self._db.save_report(session_id, markdown,
                                   json.dumps(payload), at)
        if self._commit:
            await self._snapshot(sensor_id, attacker_ip, container_id,
                                 warnings, at)
        if await self._db.session_has_content(session_id):
            await self._db.set_affinity_activity(sensor_id, attacker_ip,
                                                 True)
        return {"session_id": session_id, "changes": len(rows),
                "warnings": warnings}

    async def _collect_path(self, session_id, container_id, path, kind,
                            warnings):
        entry: dict = {"path": path, "kind": kind}
        if kind == "deleted":
            entry["note"] = "deleted; no content retrievable"
            return entry
        try:
            content, _stat = await self._pool.run_sync(
                self._pod.get_file, container_id, path)
        except IsDirError:
            entry["note"] = "directory"
            return entry
        except Exception as exc:
            # tmpfs artifacts (pid files, /run, /tmp races) vanish once
            # the container stops; that is routine, not a warning.
            if "no such file" in str(exc).lower():
                entry["note"] = "gone before collection"
            else:
                entry["note"] = f"unreadable: {exc}"
                warnings.append(f"{path}: {exc}")
                log.debug("forensics %s: %s unreadable: %s",
                          session_id, path, exc)
            return entry
        entry["size"] = len(content)
        if len(content) > self._max_file:
            entry["note"] = (f"oversized ({len(content)} bytes > "
                             f"{self._max_file}); content skipped")
            log.debug("forensics %s: %s oversized (%d bytes), skipped",
                      session_id, path, len(content))
            return entry
        try:
            ref = await self._pool.run_sync(
                self._pod.get_file, self._pool.reference_id(), path)
            before = ref[0]
        except Exception:
            before = None
        if kind == "added":
            before = None
        diff = unified_diff_text(before, content, path)
        if diff:
            entry["diff"] = diff
        elif not is_text(content):
            entry["note"] = f"binary, {len(content)} bytes"
        try:
            ref_blob = self._blobs.put_bytes(content)
        except QuotaExceeded:
            entry["note"] = "blob quota exceeded; content skipped"
            warnings.append("blob quota exceeded during capture")
            log.debug("forensics %s: blob quota hit on %s",
                      session_id, path)
            return entry
        except Exception as exc:
            entry["note"] = f"content not stored: {exc}"
            warnings.append(f"{path}: content not stored: {exc}")
            log.warning("forensics %s: blob store failed on %s: %s",
                        session_id, path, exc)
            return entry
        try:
            await self._db.add_blob(ref_blob.sha256, ref_blob.path,
                                    ref_blob.size)
            await self._db.add_session_file(
                session_id, f"container:{path}", ref_blob.sha256,
                ref_blob.size,
                datetime.datetime.now(datetime.timezone.utc))
        except Exception as exc:
            entry["note"] = f"file record not stored: {exc}"
            warnings.append(f"{path}: file record not stored: {exc}")
            log.warning("forensics %s: db write failed on %s: %s",
                        session_id, path, exc)
            return entry
        entry["sha256"] = ref_blob.sha256
        return entry

    async def _collect_export(self, session_id, container_id, changes,
                              warnings):
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(prefix="carbide-export-",
                                          suffix=".tar", delete=False)
        tmp.close()
        try:
            await self._pool.run_sync(self._pod.export_to, container_id,
                                      tmp.name)
            with open(tmp.name, "rb") as fh:
                data = fh.read()
            try:
                ref = self._blobs.put_bytes(data)
            except QuotaExceeded:
                warnings.append("blob quota exceeded; full export skipped")
                log.debug("forensics %s: full export skipped (blob quota)",
                          session_id)
                return
            await self._db.add_blob(ref.sha256, ref.path, ref.size)
            await self._db.add_session_file(
                session_id, "container:full-export.tar", ref.sha256,
                ref.size, datetime.datetime.now(datetime.timezone.utc))
            changes.append({"path": "<full export>", "kind": "export",
                            "size": len(data), "sha256": ref.sha256})
            log.debug("forensics %s: full export stored (%d bytes)",
                      session_id, len(data))
        except Exception as exc:
            warnings.append(f"full export failed: {exc}")
            log.debug("forensics %s: full export failed: %s",
                      session_id, exc)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def _render(self, session_id, sensor_id, ip, container_id, reason, at,
                changes, warnings):
        lines = [
            f"# Forensic report — session {session_id}",
            "",
            f"- sensor: {sensor_id}",
            f"- attacker: {ip}",
            f"- container: {container_id}",
            f"- captured: {at.isoformat()}",
            f"- reason: {reason or 'session end'}",
            "",
            f"## Changes ({len(changes)})",
            "",
        ]
        for entry in changes:
            marker = {"added": "A", "deleted": "D", "changed": "C",
                      "export": "E"}.get(entry["kind"], "?")
            detail = entry.get("note") or (
                f'{entry.get("size", 0)} bytes'
                + (f', sha256:{entry["sha256"][:16]}…'
                   if entry.get("sha256") else ""))
            lines.append(f"- [{marker}] {entry['path']} ({detail})")
        diffs = [e for e in changes if e.get("diff")]
        if diffs:
            lines += ["", "## Diffs", ""]
            for entry in diffs:
                lines += [f"### {entry['path']}", "", "```diff",
                          entry["diff"], "```", ""]
        if warnings:
            lines += ["## Warnings", ""]
            lines += [f"- {w}" for w in warnings]
        payload = {
            "session_id": session_id, "sensor_id": sensor_id,
            "attacker_ip": ip, "container_id": container_id,
            "reason": reason, "at": at.isoformat(), "changes": changes,
            "warnings": warnings,
        }
        return "\n".join(lines) + "\n", payload

    async def _report_unavailable(self, session_id, sensor_id, ip,
                                  container_id, reason, error, at):
        log.warning("forensics unavailable for session %s: %s",
                    session_id, error)
        warnings = [error]
        markdown, payload = self._render(
            session_id, sensor_id, ip, container_id, reason, at, [], warnings)
        await self._db.save_report(session_id, markdown,
                                   json.dumps(payload), at)
        return {"session_id": session_id, "changes": 0, "warnings": warnings}

    async def snapshot_now(self, sensor_id: str, ip: str,
                           container_id: str) -> str:
        """Console entrypoint: commit one snapshot on demand; returns tag."""
        at = datetime.datetime.now(datetime.timezone.utc)
        warnings: list = []
        tag = await self._snapshot(sensor_id, ip, container_id,
                                   warnings, at)
        if tag is None:
            raise PodmanError(warnings[0] if warnings else "snapshot failed")
        return tag

    async def _snapshot(self, sensor_id, ip, container_id, warnings, at):
        tag = (f"carbide-snap-{_safe_tag(sensor_id)}-{_safe_tag(ip)}-"
               f"{at.strftime('%Y%m%d-%H%M%S-%f')}")
        try:
            await self._pool.run_sync(self._pod.commit, container_id, tag)
        except Exception as exc:
            log.warning("snapshot %s failed: %s", tag, exc)
            warnings.append(f"snapshot failed: {exc}")
            return None
        log.info("snapshot %s created", tag)
        await self._db.add_snapshot(sensor_id, ip, container_id, tag)
        snaps = await self._db.list_snapshots(sensor_id, ip)
        while len(snaps) > self._retention:
            oldest = snaps.pop(0)[0]
            await self._pool.run_sync(self._pod.remove_image, oldest)
            await self._db.delete_snapshot(oldest)
            log.debug("pruned snapshot %s (retention %d)",
                      oldest, self._retention)
        return tag
