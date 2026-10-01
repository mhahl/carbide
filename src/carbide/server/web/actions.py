"""Console mutation handlers (POST). Every action info-logs who did
what to which target (W4: log lines are the audit trail) and returns a
small alert fragment the page swaps into its status area.
"""
import asyncio
import json
import logging
import secrets
from urllib.parse import quote

from aiohttp import web

from .auth import hash_password, require_auth
from .views import render

log = logging.getLogger("carbide.server.web")


def _alert(request, ok: bool, message: str):
    return render(request, "_alert.html",
                  {"ok": ok, "message": message})


def _as_int(value, default, lo=None, hi=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    if lo is not None and number < lo:
        return default
    if hi is not None and number > hi:
        return default
    return number


def _emit(request, name, **data):
    bus = request.app.get("bus")
    if bus is not None:
        bus.publish(name, data)


# -- containers / affinities ---------------------------------------------------
@require_auth
async def container_action(request):
    cid = request.match_info["id"]
    op = request.match_info["op"]
    user = request["user"]["username"]
    if op not in ("stop", "start", "restart"):
        return _alert(request, False, f"unknown op {op}")
    run = request.app["pool"].run_sync
    pod = request.app["pod"]
    try:
        if op in ("stop", "restart"):
            await run(pod.stop, cid)
            _emit(request, "container.stopped", container_id=cid)
        if op in ("start", "restart"):
            await run(pod.start, cid)
            _emit(request, "container.started", container_id=cid)
    except Exception as exc:
        log.warning("console %s: container %s %s failed: %s",
                    user, op, cid[:12], exc)
        return _alert(request, False, f"{op} failed: {exc}")
    log.info("console %s: container %s %s", user, op, cid[:12])
    past = {"stop": "stopped", "start": "started",
            "restart": "restarted"}[op]
    return _alert(request, True, f"container {cid[:12]} {past}")


@require_auth
async def affinity_evict(request):
    form = await request.post()
    sensor_id = (form.get("sensor_id") or "").strip()
    ip = (form.get("ip") or "").strip()
    user = request["user"]["username"]
    if not sensor_id or not ip:
        return _alert(request, False, "sensor and ip required")
    if await request.app["db"].get_affinity(sensor_id, ip) is None:
        return _alert(request, False,
                      f"no affinity for {sensor_id}/{ip}")
    try:
        await request.app["eviction"].evict_now(
            sensor_id, ip, f"manual evict by {user}")
    except Exception as exc:
        log.warning("console %s: evict %s/%s failed: %s",
                    user, sensor_id, ip, exc)
        return _alert(request, False, f"evict failed: {exc}")
    log.info("console %s: evicted %s/%s", user, sensor_id, ip)
    return _alert(request, True, f"evicted {sensor_id}/{ip}")


@require_auth
async def snapshot_now(request):
    form = await request.post()
    cid = (form.get("container_id") or "").strip()
    sensor_id = (form.get("sensor_id") or "").strip()
    ip = (form.get("ip") or "").strip()
    user = request["user"]["username"]
    if not cid or not sensor_id or not ip:
        return _alert(request, False, "container, sensor and ip required")
    try:
        tag = await request.app["forensics"].snapshot_now(
            sensor_id, ip, cid)
    except Exception as exc:
        log.warning("console %s: snapshot %s failed: %s",
                    user, cid[:12], exc)
        return _alert(request, False, f"snapshot failed: {exc}")
    log.info("console %s: snapshot %s of %s", user, tag, cid[:12])
    return _alert(request, True, f"snapshot {tag} created")


@require_auth
async def session_kill(request):
    sid = request.match_info["id"]
    user = request["user"]["username"]
    row = await request.app["db"].get_session(sid)
    if row is None:
        return _alert(request, False, "no such session")
    sensor_id = row[1]
    sent = await request.app["api"].notify_sensor(
        sensor_id, "kill_session", session_id=sid)
    if not sent:
        return _alert(request, False,
                      f"sensor {sensor_id} not connected")
    log.info("console %s: kill_session %s via %s", user, sid, sensor_id)
    return _alert(request, True, f"kill sent for session {sid}")


@require_auth
async def squid_scan(request):
    from ..vt import (VTAuthError, VTError, VTQuotaExceeded, VTQueue,
                      build_client, resolve_vt_key)
    user = request["user"]["username"]
    db = request.app["db"]
    cfg = request.app["cfg"]
    try:
        hit_id = int(request.match_info["id"])
    except ValueError:
        return _alert(request, False, "bad hit id")
    hit = await db.get_squid_hit(hit_id)
    if hit is None:
        return _alert(request, False, "no such squid hit")
    url = hit[6]
    if not url or len(url) > 2048 or not url.startswith(
            ("http://", "https://")):
        return _alert(request, False, "hit has no scannable url")
    existing = await db.get_vt_url_scan(url)
    if existing is not None and existing["status"] in (
            "malicious", "suspicious", "clean"):
        return _alert(request, True,
                      f"already scanned: {existing['status']}")
    if existing is not None and existing["status"] == "pending":
        return _alert(request, True,
                      "already submitted, awaiting verdict")
    key = await resolve_vt_key(db, cfg)
    if not key:
        return _alert(request, False, "no api key set")
    client = build_client(
        cfg, db, transport=request.app.get("vt_transport"), api_key=key)
    queue = VTQueue(db, request.app["blobs"], cfg, client=client)
    try:
        row = await queue.scan_url(url)
    except VTAuthError:
        log.info("console %s: url scan key rejected", user)
        return _alert(request, False, "key rejected 401")
    except VTQuotaExceeded:
        return _alert(request, False, "daily quota exhausted")
    except VTError as exc:
        log.warning("console %s: url scan failed: %s", user, exc)
        return _alert(request, False, f"scan failed: {exc}")
    log.info("console %s: scanned url %.60s: %s", user, url,
             row["status"])
    if row["status"] == "pending":
        return _alert(request, True,
                      "submitted; verdict lands next worker pass")
    return _alert(request, True, f"verdict: {row['status']}")


@require_auth
async def file_scan(request):
    from ..vt import (VTAuthError, VTError, VTQuotaExceeded, VTQueue,
                      build_client, resolve_vt_key)
    user = request["user"]["username"]
    db = request.app["db"]
    cfg = request.app["cfg"]
    try:
        file_id = int(request.match_info["id"])
    except ValueError:
        return _alert(request, False, "bad file id")
    row = await db.get_session_file(file_id)
    if row is None:
        return _alert(request, False, "no such file")
    _fid, _sid, name, sha, size, _at = row
    if not sha:
        return _alert(request, False, "file has no stored content")
    existing = await db.get_vt_scan(sha)
    if existing is not None and existing["status"] in (
            "malicious", "suspicious", "clean", "skipped"):
        return _alert(request, True,
                      f"already scanned: {existing['status']}")
    if existing is not None and existing["status"] == "pending":
        return _alert(request, True,
                      "already submitted, awaiting verdict")
    key = await resolve_vt_key(db, cfg)
    if not key:
        return _alert(request, False, "no api key set")
    client = build_client(
        cfg, db, transport=request.app.get("vt_transport"), api_key=key)
    queue = VTQueue(db, request.app["blobs"], cfg, client=client)
    try:
        # Deliberately bypasses the sensor-origin auto-scan filter:
        # an explicit operator click scans any stored blob.
        scanned = await queue.scan_file(sha, size)
    except VTAuthError:
        log.info("console %s: file scan key rejected", user)
        return _alert(request, False, "key rejected 401")
    except VTQuotaExceeded:
        return _alert(request, False, "daily quota exhausted")
    except VTError as exc:
        log.warning("console %s: file scan failed: %s", user, exc)
        return _alert(request, False, f"scan failed: {exc}")
    log.info("console %s: scanned file %.40s: %s", user, name,
             scanned["status"])
    if scanned["status"] == "pending":
        return _alert(request, True,
                      "submitted; verdict lands next worker pass")
    if scanned["status"] == "skipped":
        return _alert(request, True, f"skipped: {scanned['error']}")
    return _alert(request, True, f"verdict: {scanned['status']}")


# -- managed sensors -------------------------------------------------------------
def _sensor_form(form) -> tuple:
    """Returns (record dict, error). Record holds DB-ready values."""
    from .sshmgmt import MgmtError, valid_image_tag
    sensor_id = (form.get("sensor_id") or "").strip()
    ssh_host = (form.get("ssh_host") or "").strip()
    if not sensor_id:
        return None, "sensor id required"
    if not ssh_host:
        return None, "ssh host required"
    try:
        image_tag = valid_image_tag(form.get("image_tag"))
    except MgmtError as exc:
        return None, str(exc)
    try:
        probability = float(form.get("accept_probability") or 0.05)
    except ValueError:
        return None, "accept probability must be a number"
    if not 0.0 <= probability <= 1.0:
        return None, "accept probability must be 0..1"
    passwords = [line.strip()
                 for line in (form.get("passwords") or "").splitlines()
                 if line.strip()]
    return {
        "sensor_id": sensor_id, "ssh_host": ssh_host,
        "ssh_port": _as_int(form.get("ssh_port"), 22, 1, 65535),
        "ssh_user": (form.get("ssh_user") or "").strip(),
        "remote_dir": (form.get("remote_dir") or "").strip(),
        "listen_addr": (form.get("listen_addr") or "0.0.0.0").strip(),
        "listen_port": _as_int(form.get("listen_port"), 2222, 1, 65535),
        "server_host": (form.get("server_host") or "").strip(),
        "server_port": _as_int(form.get("server_port"), 8440, 1, 65535),
        "auth_passwords": json.dumps(passwords),
        "accept_probability": probability,
        "notes": (form.get("notes") or "").strip(),
        "image_tag": image_tag,
    }, ""


@require_auth
async def sensor_save(request):
    form = await request.post()
    user = request["user"]["username"]
    record, error = _sensor_form(form)
    if record is None:
        raise web.HTTPFound(
            f"/sensors/new?sensor_id={form.get('sensor_id', '')}"
            f"&error={error}")
    await request.app["db"].upsert_managed_sensor(**record)
    log.info("console %s: saved managed sensor %s",
             user, record["sensor_id"])
    raise web.HTTPFound(f"/sensors/{record['sensor_id']}?notice=saved")


@require_auth
async def sensor_delete(request):
    sid = request.match_info["id"]
    await request.app["db"].delete_managed_sensor(sid)
    log.info("console %s: deleted managed sensor %s",
             request["user"]["username"], sid)
    raise web.HTTPFound("/sensors?notice=deleted")


def _mgmt_or_error(request):
    mgmt = request.app["mgmt"]
    if not mgmt.enabled:
        return None
    return mgmt


@require_auth
async def sensor_push(request):
    sid = request.match_info["id"]
    user = request["user"]["username"]
    mgmt = _mgmt_or_error(request)
    if mgmt is None:
        return _alert(request, False,
                      "sensor management not configured "
                      "([sensor_mgmt] enabled + key_path)")
    sensor = await request.app["db"].get_managed_sensor(sid)
    if sensor is None:
        return _alert(request, False, "no such managed sensor")
    try:
        result = await mgmt.push_config(sensor)
    except Exception as exc:
        return _alert(request, False, f"push failed: {exc}")
    log.info("console %s: push to %s: %s", user, sid,
             "ok" if result["ok"] else result["output"][-200:])
    if not result["ok"]:
        return render(request, "_alert.html",
                      {"ok": False, "message": f"push to {sid} failed",
                       "output": result["output"]})
    return render(request, "_alert.html",
                  {"ok": True, "message": f"config pushed to {sid}",
                   "output": result["output"]})


@require_auth
async def sensor_restart(request):
    sid = request.match_info["id"]
    user = request["user"]["username"]
    mgmt = _mgmt_or_error(request)
    if mgmt is None:
        return _alert(request, False,
                      "sensor management not configured "
                      "([sensor_mgmt] enabled + key_path)")
    sensor = await request.app["db"].get_managed_sensor(sid)
    if sensor is None:
        return _alert(request, False, "no such managed sensor")
    try:
        result = await mgmt.restart(sensor)
    except Exception as exc:
        return _alert(request, False, f"restart failed: {exc}")
    log.info("console %s: restart %s: %s", user, sid,
             "ok" if result["ok"] else result["output"][-200:])
    if not result["ok"]:
        return render(request, "_alert.html",
                      {"ok": False, "message": f"restart {sid} failed",
                       "output": result["output"]})
    return render(request, "_alert.html",
                  {"ok": True, "message": f"{sid} restarted",
                   "output": result["output"]})


@require_auth
async def sensor_update(request):
    sid = request.match_info["id"]
    user = request["user"]["username"]
    mgmt = _mgmt_or_error(request)
    if mgmt is None:
        return _alert(request, False,
                      "sensor management not configured "
                      "([sensor_mgmt] enabled + key_path)")
    sensor = await request.app["db"].get_managed_sensor(sid)
    if sensor is None:
        return _alert(request, False, "no such managed sensor")
    try:
        result = await mgmt.update_image(sensor)
    except Exception as exc:
        return _alert(request, False, f"update failed: {exc}")
    log.info("console %s: update %s image: %s", user, sid,
             "ok" if result["ok"] else result["output"][-200:])
    if not result["ok"]:
        return render(request, "_alert.html",
                      {"ok": False,
                       "message": f"image update {sid} failed",
                       "output": result["output"]})
    return render(request, "_alert.html",
                  {"ok": True,
                   "message": f"{sid} image updated",
                   "output": result["output"]})


async def _run_provision(app, pid: str, sensor: dict, user: str):
    job = app["provisions"][pid]
    try:
        result = await app["mgmt"].provision(sensor)
    except Exception as exc:  # never leave the job hanging
        result = {"ok": False, "output": str(exc)}
    job.update({"status": "done" if result["ok"] else "error",
                "output": result.get("output", "")})
    log.info("console %s: provision %s: %s", user,
             sensor["sensor_id"],
             "ok" if result["ok"] else "failed")


@require_auth
async def sensor_provision(request):
    sid = request.match_info["id"]
    user = request["user"]["username"]
    mgmt = _mgmt_or_error(request)
    if mgmt is None:
        return _alert(request, False,
                      "sensor management not configured "
                      "([sensor_mgmt] enabled + key_path)")
    sensor = await request.app["db"].get_managed_sensor(sid)
    if sensor is None:
        return _alert(request, False, "no such managed sensor")
    if not sensor["remote_dir"]:
        return _alert(request, False,
                      "remote_dir is required for provisioning")
    try:
        mgmt.files_dir()
    except Exception as exc:
        return _alert(request, False, str(exc))
    pid = secrets.token_hex(8)
    request.app["provisions"][pid] = {
        "sensor_id": sid, "status": "running", "output": "",
        "user": user}
    asyncio.create_task(_run_provision(
        request.app, pid, sensor, user))
    log.info("console %s: provision %s started (%s)", user, sid, pid)
    return render(request, "_provision.html",
                  {"pid": pid,
                   "job": request.app["provisions"][pid]})


# -- console users ---------------------------------------------------------------
@require_auth
async def user_create(request):
    form = await request.post()
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    if not username or len(username) > 64:
        raise web.HTTPFound("/users?error=bad+username")
    if len(password) < 8:
        raise web.HTTPFound("/users?error=password+min+8+chars")
    if await request.app["db"].get_web_user_by_name(username):
        raise web.HTTPFound("/users?error=user+exists")
    await request.app["db"].create_web_user(
        username, hash_password(password))
    log.info("console %s: created user %s",
             request["user"]["username"], username)
    raise web.HTTPFound("/users?notice=created")


@require_auth
async def user_disable(request):
    user_id = int(request.match_info["id"])
    me = request["user"]
    if user_id == me["id"]:
        raise web.HTTPFound("/users?error=cannot+disable+self")
    enabled = [u for u in await request.app["db"].list_web_users()
               if not u["disabled"]]
    if len(enabled) <= 1 and any(u["id"] == user_id for u in enabled):
        raise web.HTTPFound("/users?error=last+enabled+user")
    await request.app["db"].set_web_user_disabled(user_id, True)
    log.info("console %s: disabled user %d", me["username"], user_id)
    raise web.HTTPFound("/users?notice=disabled")


@require_auth
async def user_enable(request):
    user_id = int(request.match_info["id"])
    await request.app["db"].set_web_user_disabled(user_id, False)
    log.info("console %s: enabled user %d",
             request["user"]["username"], user_id)
    raise web.HTTPFound("/users?notice=enabled")


@require_auth
async def user_password(request):
    user_id = int(request.match_info["id"])
    form = await request.post()
    password = form.get("password") or ""
    if len(password) < 8:
        raise web.HTTPFound("/users?error=password+min+8+chars")
    await request.app["db"].set_web_user_password(
        user_id, hash_password(password))
    log.info("console %s: reset password for user %d",
             request["user"]["username"], user_id)
    raise web.HTTPFound("/users?notice=password+updated")


# -- server settings -------------------------------------------------------
@require_auth
async def vt_key_save(request):
    from ..vt import VT_KEY_SETTING
    form = await request.post()
    key = (form.get("api_key") or "").strip()
    user = request["user"]["username"]
    if len(key) < 16 or len(key) > 256 or any(ch.isspace() for ch in key):
        raise web.HTTPFound("/settings?error=key+looks+invalid")
    await request.app["db"].set_setting(VT_KEY_SETTING, key)
    log.info("console %s: saved virustotal api key (…%s)",
             user, key[-4:])
    raise web.HTTPFound("/settings?notice=key+saved")


@require_auth
async def vt_key_clear(request):
    from ..vt import VT_KEY_SETTING
    user = request["user"]["username"]
    await request.app["db"].delete_setting(VT_KEY_SETTING)
    log.info("console %s: cleared console virustotal api key", user)
    raise web.HTTPFound("/settings?notice=key+cleared")


@require_auth
async def carto_key_save(request):
    from .geomap import CARTO_KEY_SETTING
    form = await request.post()
    key = (form.get("api_key") or "").strip()
    user = request["user"]["username"]
    # Deliberately looser than the VT rule: CARTO key formats vary,
    # so anything non-blank without whitespace is accepted.
    if not key or len(key) > 256 or any(ch.isspace() for ch in key):
        raise web.HTTPFound("/settings?error=key+looks+invalid")
    await request.app["db"].set_setting(CARTO_KEY_SETTING, key)
    log.info("console %s: saved carto api key (…%s)", user, key[-4:])
    raise web.HTTPFound("/settings?notice=carto+key+saved")


@require_auth
async def carto_key_clear(request):
    from .geomap import CARTO_KEY_SETTING
    user = request["user"]["username"]
    await request.app["db"].delete_setting(CARTO_KEY_SETTING)
    log.info("console %s: cleared carto api key", user)
    raise web.HTTPFound("/settings?notice=carto+key+cleared")


@require_auth
async def vt_key_verify(request):
    from ..vt import (VTAuthError, VTError, VTQuotaExceeded, build_client,
                      resolve_vt_key)
    user = request["user"]["username"]
    db = request.app["db"]
    cfg = request.app["cfg"]
    key = await resolve_vt_key(db, cfg)
    if not key:
        raise web.HTTPFound("/settings?error=no+api+key+set")
    client = build_client(cfg, db,
                          transport=request.app.get("vt_transport"),
                          api_key=key)
    try:
        # Any answer (report or 404) proves the key; only 401 fails it.
        await client.lookup("f" * 64)
    except VTAuthError:
        log.info("console %s: virustotal key verify rejected", user)
        raise web.HTTPFound("/settings?error=key+rejected+401")
    except VTQuotaExceeded:
        raise web.HTTPFound("/settings?error=daily+quota+exhausted")
    except VTError as exc:
        log.warning("console %s: virustotal key verify failed: %s",
                    user, exc)
        raise web.HTTPFound("/settings?error=verify+failed")
    log.info("console %s: virustotal key verified", user)
    raise web.HTTPFound("/settings?notice=key+valid")


@require_auth
async def honey_image_save(request):
    from ..pool import HONEY_IMAGE_SETTING
    form = await request.post()
    ref = (form.get("image") or "").strip()
    user = request["user"]["username"]
    if not ref or len(ref) > 256 or any(ch.isspace() for ch in ref):
        raise web.HTTPFound("/settings?error=image+ref+looks+invalid")
    await request.app["db"].set_setting(HONEY_IMAGE_SETTING, ref)
    log.info("console %s: set honeypot image to %s", user, ref)
    try:
        await request.app["pool"].refresh_reference()
    except Exception as exc:
        log.warning("console %s: baseline refresh after image save "
                    "failed: %s", user, exc)
        raise web.HTTPFound(
            "/settings?notice=image+saved+but+baseline+refresh+failed")
    raise web.HTTPFound("/settings?notice=honeypot+image+saved")


@require_auth
async def honey_image_clear(request):
    from ..pool import HONEY_IMAGE_SETTING
    user = request["user"]["username"]
    await request.app["db"].delete_setting(HONEY_IMAGE_SETTING)
    log.info("console %s: cleared console honeypot image", user)
    try:
        await request.app["pool"].refresh_reference()
    except Exception as exc:
        log.warning("console %s: baseline refresh after image clear "
                    "failed: %s", user, exc)
        raise web.HTTPFound(
            "/settings?notice=image+cleared+but+baseline+refresh+failed")
    raise web.HTTPFound("/settings?notice=honeypot+image+cleared")


@require_auth
async def honey_image_pull(request):
    pool = request.app["pool"]
    user = request["user"]["username"]
    ref = await pool.current_image()
    try:
        await pool.run_sync(request.app["pod"].pull_image, ref)
    except Exception as exc:
        log.warning("console %s: honeypot image pull failed: %s", user, exc)
        raise web.HTTPFound("/settings?error=" + quote(
            f"pull failed: {exc}"))
    log.info("console %s: pulled honeypot image %s", user, ref)
    raise web.HTTPFound("/settings?notice=" + quote(f"pulled {ref}"))


@require_auth
async def forensics_prefixes_save(request):
    import json as _json
    from ..forensics import VOLATILE_SETTING
    form = await request.post()
    user = request["user"]["username"]
    lines = [(ln.strip()) for ln in
             (form.get("prefixes") or "").splitlines()]
    prefixes = [ln for ln in lines if ln]
    for prefix in prefixes:
        if (not prefix.startswith("/") or len(prefix) > 256
                or any(ch.isspace() for ch in prefix)):
            raise web.HTTPFound("/settings?error=" + quote(
                f"bad prefix {prefix!r}: must start with /"))
    db = request.app["db"]
    if not prefixes:
        await db.delete_setting(VOLATILE_SETTING)
        log.info("console %s: reset forensic exclusions to defaults",
                 user)
        raise web.HTTPFound("/settings?notice=exclusions+reset")
    await db.set_setting(VOLATILE_SETTING, _json.dumps(prefixes))
    log.info("console %s: saved %d forensic exclusion prefixes",
             user, len(prefixes))
    raise web.HTTPFound("/settings?notice=exclusions+saved")


@require_auth
async def sessions_clear(request):
    user = request["user"]["username"]
    counts = await request.app["db"].clear_sessions()
    total = sum(counts.values())
    log.info("console %s: cleared sessions (%d rows: %s)", user, total,
             ", ".join(f"{t}={c}" for t, c in sorted(counts.items())
                       if c))
    raise web.HTTPFound(
        f"/settings?notice=cleared+{counts.get('sessions', 0)}+sessions")


@require_auth
async def forensics_prefixes_reset(request):
    from ..forensics import VOLATILE_SETTING
    user = request["user"]["username"]
    await request.app["db"].delete_setting(VOLATILE_SETTING)
    log.info("console %s: reset forensic exclusions to defaults", user)
    raise web.HTTPFound("/settings?notice=exclusions+reset")
