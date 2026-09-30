"""Console page handlers (GET): analyst views, podman state, sensors,
logs, users, fragments, and SSE streams."""
import asyncio
import datetime
import html
import json
import logging

from aiohttp import web

from .auth import COOKIE, current_user, require_auth, token_sha

log = logging.getLogger("carbide.server.web")

SESSION_COLS = ("session_id", "sensor_id", "attacker_ip", "username",
                "container_id", "fresh", "over_quota", "started_at",
                "ended_at", "end_reason")


def _srow(tup):
    return dict(zip(SESSION_COLS, tup))


def _page_params(request, default_limit=50):
    try:
        page = max(1, int(request.query.get("page", "1")))
    except ValueError:
        page = 1
    return page, (page - 1) * default_limit, default_limit


def _base_query(request):
    return "&".join(f"{k}={v}" for k, v in request.query.items()
                    if k != "page")


def _sort_links(request, allowed: dict, default: str):
    """Server-side sort state for paginated tables.

    allowed maps column -> default-descending. Returns (sort, descending,
    links) where links[col] = {"url", "ind", "aria"}; sort links reset
    to page 1 and keep the other filters.
    """
    sort = request.query.get("sort") or default
    if sort not in allowed:
        sort = default
    descending = (request.query.get("dir") or
                  ("desc" if allowed[sort] else "asc")) != "asc"
    base = "&".join(f"{k}={v}" for k, v in request.query.items()
                    if k not in ("page", "sort", "dir"))
    links = {}
    for col, col_desc in allowed.items():
        if col == sort:
            ndir = "asc" if descending else "desc"
            ind = "▼" if descending else "▲"
            aria = "descending" if descending else "ascending"
        else:
            ndir = "desc" if col_desc else "asc"
            ind, aria = "", "none"
        query = f"{base}&" if base else ""
        links[col] = {"url": f"{query}sort={col}&dir={ndir}", "ind": ind,
                      "aria": aria}
    return sort, descending, links


def render(request, name, ctx=None, status=200):
    env = request.app["jinja"]
    template = env.get_template(name)
    body = template.render(user=request.get("user"),
                           mgmt=request.app["mgmt"].status(),
                           nav_path=request.path,
                           **(ctx or {}))
    return web.Response(text=body, content_type="text/html",
                        status=status)


# -- auth pages ------------------------------------------------------
async def login_get(request):
    if await current_user(request):
        raise web.HTTPFound(request.query.get("next") or "/")
    return render(request, "login.html",
                  {"next": request.query.get("next") or "", "error": ""})


async def login_post(request):
    form = await request.post()
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    nxt = form.get("next") or "/"
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/"
    from .auth import verify_password, new_token
    user = await request.app["db"].get_web_user_by_name(username)
    if user is None or user["disabled"] or not verify_password(
            password, user["pw_hash"]):
        log.info("console login rejected for %s", username or "-")
        return render(request, "login.html",
                      {"next": nxt, "error": "bad username or password"})
    await request.app["db"].delete_expired_web_sessions()
    token = new_token()
    ttl = request.app["cfg"].get("web.session_ttl_hours", 12)
    expires = (datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(hours=ttl))
    await request.app["db"].create_web_session(
        token_sha(token), user["id"], expires)
    log.info("console login: %s", username)
    resp = web.HTTPFound(nxt)
    resp.set_cookie(COOKIE, token, httponly=True, samesite="Lax",
                    path="/", max_age=ttl * 3600)
    raise resp


async def logout(request):
    token = request.cookies.get(COOKIE, "")
    if token:
        await request.app["db"].delete_web_session(token_sha(token))
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE, path="/")
    raise resp


# -- dashboard ---------------------------------------------------------
@require_auth
async def dashboard(request):
    db = request.app["db"]
    day_ago = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(hours=24))
    try:
        pods = await request.app["pool"].run_sync(
            request.app["pod"].list_all_containers)
        running = sum(1 for c in pods if c["status"] == "running")
    except Exception as exc:
        log.debug("dashboard podman list failed: %s", exc)
        running, pods = 0, None
    ctx = {
        "open_sessions": await db.count_open_sessions(),
        "sessions_24h": await db.count_sessions_since(day_ago),
        "affinities": await db.count_affinities(),
        "auth_24h": await db.count_auth_since(day_ago),
        "containers_running": running,
        "podman_ok": pods is not None,
        "recent": await _recent_with_intel(db),
        "auth": [dict(zip(
            ("id", "session_id", "sensor_id", "username", "password",
             "accepted", "matched", "at"), t))
            for t in await db.list_auth_attempts(limit=10)],
        "squid": [dict(zip(
            ("id", "session_id", "sensor_id", "container_ip", "at",
             "method", "url", "status", "size", "mime"), t))
            for t in await db.list_squid_hits(limit=8)],
        "logs": request.app["logring"].lines(15),
        "live": request.app["api"].live_sensors(),
    }
    return render(request, "dashboard.html", ctx)


# -- sessions ------------------------------------------------------------
@require_auth
async def sessions_list(request):
    db = request.app["db"]
    sensor = request.query.get("sensor") or ""
    ip = request.query.get("ip") or ""
    open_only = request.query.get("open") == "1"
    show_empty = request.query.get("empty") == "1"
    page, offset, limit = _page_params(request)
    sort, descending, links = _sort_links(request, {
        "session_id": False, "sensor_id": False, "attacker_ip": False,
        "username": False, "container_id": False, "started_at": True,
        "ended_at": True}, "started_at")
    rows = await db.list_sessions(
        sensor_id=sensor or None, ip=ip or None, open_only=open_only,
        require_container=not show_empty,
        limit=limit + 1, offset=offset, sort=sort, descending=descending)
    return render(request, "sessions.html", {
        "rows": [_srow(t) for t in rows[:limit]],
        "sensor": sensor, "ip": ip, "open_only": open_only,
        "show_empty": show_empty,
        "page": page, "has_more": len(rows) > limit,
        "base_query": _base_query(request), "sort_links": links})


@require_auth
async def session_detail(request):
    db = request.app["db"]
    sid = request.match_info["id"]
    row = await db.get_session(sid)
    if row is None:
        return render(request, "error.html",
                      {"message": f"no such session {sid}"}, status=404)
    session = _srow(row)
    chunks = await db.get_transcript(sid, limit=500)
    transcript = [{
        "id": c[0], "channel": c[1], "direction": c[2], "stream": c[3],
        "seq": c[4], "at": c[6],
        "text": c[5].decode("utf-8", "replace") if isinstance(c[5], bytes)
        else str(c[5])} for c in chunks]
    raw_files = await db.list_session_files(sid)
    verdicts = await db.get_vt_scans([f[2] for f in raw_files])
    files = []
    for f in raw_files:
        entry = dict(zip(("id", "name", "sha", "size", "at"), f))
        vt = verdicts.get(entry["sha"]) if entry["sha"] else None
        entry["vt"] = vt["status"] if vt else ""
        entry["vt_malicious"] = vt["malicious"] if vt else 0
        entry["vt_link"] = vt["permalink"] if vt else ""
        files.append(entry)
    attempts = [dict(zip(
        ("id", "session_id", "sensor_id", "username", "password",
         "accepted", "matched", "at"), t))
        for t in await db.list_auth_attempts(session_id=sid, limit=500)]
    hits = [dict(zip(
        ("id", "session_id", "sensor_id", "container_ip", "at",
         "method", "url", "status", "size", "mime"), t))
        for t in await db.list_squid_hits(session_id=sid, limit=500)]
    url_verdicts = await db.get_vt_url_scans([h["url"] for h in hits])
    for h in hits:
        vt = url_verdicts.get(h["url"])
        h["vt"] = vt["status"] if vt else ""
        h["vt_malicious"] = vt["malicious"] if vt else 0
        h["vt_link"] = vt["permalink"] if vt else ""
    diffs = [{"path": p, "kind": k}
             for p, k in await db.get_diff_rows(sid)]
    report = await db.get_report(sid)
    detected = sum(1 for f in files
                   if f["vt"] in ("malicious", "suspicious"))
    return render(request, "session_detail.html", {
        "s": session, "transcript": transcript, "files": files,
        "files_detected": detected,
        "attempts": attempts, "hits": hits, "diffs": diffs,
        "report": report[0] if report else "",
        "last_chunk": chunks[-1][0] if chunks else 0})


# -- attackers ---------------------------------------------------------
@require_auth
async def attackers_list(request):
    db = request.app["db"]
    page, offset, limit = _page_params(request)
    sort, descending, links = _sort_links(request, {
        "attacker_ip": False, "sessions": True, "last_seen": True,
        "files": True, "malicious": True, "intel": False}, "last_seen")
    rows = await db.list_attackers(limit=limit + 1, offset=offset,
                                   sort=sort, descending=descending)
    return render(request, "attackers.html", {
        "rows": [dict(zip(("ip", "sessions", "last_seen", "files",
                           "malicious", "intel"), t))
                 for t in rows[:limit]],
        "page": page, "has_more": len(rows) > limit,
        "base_query": _base_query(request), "sort_links": links})


@require_auth
async def attacker_detail(request):
    db = request.app["db"]
    ip = request.match_info["ip"]
    sessions = [_srow(t) for t in
                await db.list_sessions(ip=ip, limit=200)]
    intel = await db.get_ip_intel(ip)
    if not sessions and intel is None:
        return render(request, "error.html",
                      {"message": f"no such attacker {ip}"}, status=404)
    files = [dict(zip(("id", "session_id", "name", "sha", "size", "at",
                        "vt", "vt_malicious", "vt_suspicious",
                        "vt_link"), f))
             for f in await db.list_files_by_ip(ip)]
    ports = []
    if intel is not None:
        try:
            ports = json.loads(intel["open_ports"] or "[]")
        except (ValueError, TypeError):
            ports = []
    return render(request, "attacker_detail.html", {
        "ip": ip, "intel": intel, "ports": ports, "sessions": sessions,
        "files": files})


@require_auth
async def transcript_fragment(request):
    """Live tail fragment, polled by the session page while open."""
    db = request.app["db"]
    sid = request.match_info["id"]
    try:
        after = int(request.query.get("after", "0"))
    except ValueError:
        after = 0
    chunks = await db.get_transcript(sid, after_id=after, limit=200)
    rows = [{
        "id": c[0], "channel": c[1], "direction": c[2],
        "text": c[5].decode("utf-8", "replace") if isinstance(c[5], bytes)
        else str(c[5])} for c in chunks]
    return render(request, "_transcript_rows.html",
                  {"rows": rows,
                   "last": chunks[-1][0] if chunks else after,
                   "sid": sid})


@require_auth
async def file_download(request):
    sha = request.match_info["sha"]
    row = await request.app["db"].get_blob(sha)
    if row is None:
        return render(request, "error.html",
                      {"message": "no such blob"}, status=404)
    _sha, _path, size = row
    name = request.query.get("name") or sha
    resp = web.StreamResponse(status=200, headers={
        "Content-Type": "application/octet-stream",
        "Content-Length": str(size),
        "Content-Disposition": f'attachment; filename="{name}"'})
    await resp.prepare(request)
    try:
        with open(request.app["blobs"].path_for(sha), "rb") as fh:
            while True:
                piece = fh.read(65536)
                if not piece:
                    break
                await resp.write(piece)
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    return resp


# -- snapshots + compare ---------------------------------------------------
@require_auth
async def snapshots_list(request):
    db = request.app["db"]
    sensor = request.query.get("sensor") or ""
    rows = await db.list_snapshots_all(sensor_id=sensor or None)
    return render(request, "snapshots.html", {
        "rows": [dict(zip(("sensor_id", "ip", "container_id", "image",
                           "created"), r)) for r in rows],
        "sensor": sensor})


@require_auth
async def compare(request):
    a_id, b_id = request.query.get("a") or "", request.query.get("b") or ""
    ctx = {"a_id": a_id, "b_id": b_id, "rows": None,
           "a_snaps": [], "b_snaps": []}
    if a_id and b_id:
        db = request.app["db"]
        a_sess = await db.get_session(a_id)
        b_sess = await db.get_session(b_id)
        if a_sess is None or b_sess is None:
            return render(request, "error.html",
                          {"message": "one of the sessions does not exist"},
                          status=404)
        a_diff = dict(await db.get_diff_rows(a_id))
        b_diff = dict(await db.get_diff_rows(b_id))
        ctx["rows"] = [{"path": p, "a": a_diff.get(p),
                        "b": b_diff.get(p)}
                       for p in sorted(set(a_diff) | set(b_diff))]
        ctx["a_snaps"] = await db.list_snapshots(_srow(a_sess)["sensor_id"],
                                                 _srow(a_sess)["attacker_ip"])
        ctx["b_snaps"] = await db.list_snapshots(_srow(b_sess)["sensor_id"],
                                                 _srow(b_sess)["attacker_ip"])
        ctx["a"] = _srow(a_sess)
        ctx["b"] = _srow(b_sess)
    return render(request, "compare.html", ctx)


# -- auth attempts + credentials ---------------------------------------------
@require_auth
async def auth_view(request):
    db = request.app["db"]
    username = request.query.get("username") or ""
    sensor = request.query.get("sensor") or ""
    accepted = request.query.get("accepted") or ""
    page, offset, limit = _page_params(request, 100)
    acc = {"1": True, "0": False}.get(accepted)
    sort, descending, links = _sort_links(request, {
        "at": True, "sensor_id": False, "username": False,
        "password": False, "accepted": True}, "at")
    rows = await db.list_auth_attempts(
        sensor_id=sensor or None, username=username or None,
        accepted=acc, limit=limit + 1, offset=offset,
        sort=sort, descending=descending)
    creds = await db.list_affinities()
    return render(request, "auth.html", {
        "rows": [dict(zip(
            ("id", "session_id", "sensor_id", "username", "password",
             "accepted", "matched", "at"), t)) for t in rows[:limit]],
        "creds": creds, "username": username, "sensor": sensor,
        "accepted": accepted, "page": page,
        "has_more": len(rows) > limit,
        "base_query": _base_query(request), "sort_links": links})


# -- podman state ------------------------------------------------------------
async def _podman_or_error(request):
    try:
        run = request.app["pool"].run_sync
        pod = request.app["pod"]
        containers = await run(pod.list_all_containers)
        images = await run(pod.list_images)
        networks = await run(pod.list_networks)
        return {"containers": sorted(
            containers, key=lambda c: c["name"]), "images": images,
            "networks": networks, "podman_ok": True}
    except Exception as exc:
        log.warning("console podman view failed: %s", exc)
        return {"containers": [], "images": [], "networks": [],
                "podman_ok": False, "podman_error": str(exc)}


@require_auth
async def podman_view(request):
    return render(request, "podman.html",
                  await _podman_or_error(request))


@require_auth
async def container_detail(request):
    cid = request.match_info["id"]
    run = request.app["pool"].run_sync
    pod = request.app["pod"]
    try:
        info = await run(pod.inspect, cid)
        status = await run(pod.status, cid)
    except Exception as exc:
        return render(request, "error.html",
                      {"message": f"inspect {cid[:12]} failed: {exc}"},
                      status=404)
    pretty = json.dumps(info, indent=2, default=str)
    nets = (info.get("NetworkSettings", {}) or {}).get("Networks", {})
    ip = ""
    for net in (nets or {}).values():
        if isinstance(net, dict) and net.get("IPAddress"):
            ip = net["IPAddress"]
            break
    aff = None
    if ip:
        try:
            aff = await request.app["db"].get_affinity_by_container_ip(ip)
        except Exception:
            aff = None
    return render(request, "container_detail.html",
                  {"cid": cid, "status": status, "pretty": pretty,
                   "ip": ip, "aff": aff})


@require_auth
async def container_diff(request):
    from ..forensics import normalize_changes
    cid = request.match_info["id"]
    try:
        raw = await request.app["pool"].run_sync(
            request.app["pod"].diff, cid)
    except Exception as exc:
        return render(request, "error.html",
                      {"message": f"diff {cid[:12]} failed: {exc}"},
                      status=404)
    rows, warnings = normalize_changes(raw)
    return render(request, "container_diff.html",
                  {"cid": cid,
                   "rows": [{"path": p, "kind": k} for p, k in rows],
                   "warnings": warnings})


@require_auth
async def container_file(request):
    from ..forensics import is_text
    from ..podman_wrap import IsDirError
    cid = request.match_info["id"]
    path = request.query.get("path") or ""
    if not path.startswith("/"):
        return render(request, "error.html",
                      {"message": "path must be absolute"}, status=400)
    try:
        content, _stat = await request.app["pool"].run_sync(
            request.app["pod"].get_file, cid, path)
    except IsDirError:
        return render(request, "error.html",
                      {"message": f"{path} is a directory"}, status=400)
    except Exception as exc:
        return render(request, "error.html",
                      {"message": f"read failed: {exc}"}, status=404)
    if request.query.get("download") == "1":
        return web.Response(
            body=content, headers={
                "Content-Type": "application/octet-stream",
                "Content-Disposition":
                    f'attachment; filename="{path.rsplit("/", 1)[-1]}"'})
    if not is_text(content):
        text, truncated = "", False
        note = f"binary file, {len(content)} bytes (download to inspect)"
    else:
        text = content.decode("utf-8", "replace")
        truncated = len(text) > 100_000
        text, note = text[:100_000], ""
    return render(request, "container_file.html",
                  {"cid": cid, "path": path, "text": text, "note": note,
                   "truncated": truncated, "size": len(content)})


# -- sensors ---------------------------------------------------------------
@require_auth
async def sensors_list(request):
    db = request.app["db"]
    live = request.app["api"].live_sensors()
    seen = {s: (f, l) for s, f, l in await db.list_sensors()}
    managed = await db.list_managed_sensors()
    unmanaged = sorted(s for s in seen if all(
        m["sensor_id"] != s for m in managed))
    return render(request, "sensors.html",
                  {"managed": managed, "live": live,
                   "seen": {s: l for s, (_f, l) in seen.items()},
                   "unmanaged": unmanaged,
                   "seen_full": {s: {"first": f, "last": l}
                                 for s, (f, l) in seen.items()}})


@require_auth
async def sensor_new(request):
    prefill = {
        "sensor_id": request.query.get("sensor_id") or "",
        "ssh_host": "", "ssh_port": 22, "ssh_user": "",
        "remote_dir": "", "listen_addr": "0.0.0.0", "listen_port": 2222,
        "server_host": "", "server_port": 8440, "passwords": "",
        "accept_probability": 0.05, "notes": "", "image_tag": "latest"}
    return render(request, "sensor_form.html",
                  {"m": prefill, "is_new": True,
                   "error": request.query.get("error") or ""})


@require_auth
async def sensor_detail(request):
    import json as _json
    sid = request.match_info["id"]
    m = await request.app["db"].get_managed_sensor(sid)
    if m is None:
        return render(request, "error.html",
                      {"message": f"no managed sensor {sid}"}, status=404)
    try:
        passwords = "\n".join(_json.loads(m["auth_passwords"] or "[]"))
    except ValueError:
        passwords = ""
    live = sid in request.app["api"].live_sensors()
    return render(request, "sensor_detail.html",
                  {"m": m, "passwords": passwords, "live": live,
                   "error": request.query.get("error") or "",
                   "notice": request.query.get("notice") or ""})


# -- logs + users ------------------------------------------------------------
@require_auth
async def logs_view(request):
    return render(request, "logs.html",
                  {"lines": request.app["logring"].lines(300)})


@require_auth
async def users_view(request):
    rows = await request.app["db"].list_web_users()
    return render(request, "users.html",
                  {"rows": rows, "error": request.query.get("error") or "",
                   "notice": request.query.get("notice") or ""})


# -- settings ----------------------------------------------------------
@require_auth
async def settings_view(request):
    from ..vt import VT_KEY_SETTING
    from ..pool import HONEY_IMAGE_SETTING, same_image_ref
    from ..forensics import VOLATILE_SETTING, parse_prefixes
    db = request.app["db"]
    cfg = request.app["cfg"]
    stored = await db.get_setting(VT_KEY_SETTING)
    file_key = cfg.section("virustotal")["api_key"] or ""
    if stored and stored.strip():
        source, masked, active = "console", "••••" + stored.strip()[-4:], True
    elif file_key:
        source, masked, active = "config file", "••••" + file_key[-4:], True
    else:
        source, masked, active = "none", "", False
    img_override = await db.get_setting(HONEY_IMAGE_SETTING)
    file_image = cfg.section("podman")["image"]
    if img_override and img_override.strip():
        honey_effective = img_override.strip()
        honey_source, honey_console_set = "console", True
    else:
        honey_effective = file_image
        honey_source, honey_console_set = "config file", False
    honey_present = None
    try:
        run = request.app["pool"].run_sync
        images = await run(request.app["pod"].list_images)
        tags = [t for img in images for t in img.get("tags", [])]
        honey_present = any(
            same_image_ref(t, honey_effective) for t in tags)
    except Exception as exc:
        log.warning("honeypot image presence check failed: %s", exc)
    raw_prefixes = await db.get_setting(VOLATILE_SETTING)
    parsed_prefixes = parse_prefixes(raw_prefixes)
    if parsed_prefixes is not None:
        prefix_source, prefix_list = "console", parsed_prefixes
    else:
        from ..forensics import VOLATILE_PREFIXES
        prefix_source, prefix_list = "defaults", VOLATILE_PREFIXES
    today = datetime.datetime.now(datetime.timezone.utc).date()
    return render(request, "settings.html", {
        "vt_source": source, "vt_masked": masked, "vt_active": active,
        "vt_console_set": bool(stored and stored.strip()),
        "vt_used": await db.vt_quota_used(today),
        "vt_cap": cfg.get("virustotal.daily_cap", 500),
        "vt_rpm": cfg.get("virustotal.requests_per_minute", 4),
        "honey_source": honey_source, "honey_effective": honey_effective,
        "honey_console_set": honey_console_set,
        "honey_present": honey_present,
        "prefix_source": prefix_source,
        "prefix_text": "\n".join(prefix_list),
        "prefix_count": len(prefix_list),
        "prefix_console_set": parsed_prefixes is not None,
        "error": request.query.get("error") or "",
        "notice": request.query.get("notice") or ""})


# -- fragments (htmx partials) -------------------------------------------------
@require_auth
async def frag_containers(request):
    return render(request, "_containers.html",
                  await _podman_or_error(request))


@require_auth
async def frag_sensors(request):
    live = request.app["api"].live_sensors()
    seen = {s: l for s, _f, l in
            await request.app["db"].list_sensors()}
    managed = await request.app["db"].list_managed_sensors()
    return render(request, "_sensors.html",
                  {"managed": managed, "live": live, "seen": seen})


async def _recent_with_intel(db, limit=10):
    """Recent sessions enriched with cached geo + PTR per attacker IP."""
    rows = [_srow(t) for t in await db.list_sessions(limit=limit)]
    ips = [r["attacker_ip"] for r in rows]
    intel = await db.get_ip_intel_many(ips)
    for row in rows:
        info = intel.get(row["attacker_ip"]) or {}
        code = info.get("country_code") or ""
        city = info.get("city") or ""
        if code and city:
            geo = f"{code} · {city}"
        else:
            geo = code or city
        row["geo"] = geo
        row["geo_org"] = info.get("org") or ""
        row["geo_country"] = info.get("country") or ""
        row["rdns"] = info.get("rdns") or ""
    return rows


@require_auth
async def frag_recent_sessions(request):
    rows = await _recent_with_intel(request.app["db"])
    return render(request, "_recent_sessions.html", {"recent": rows})


@require_auth
async def frag_provision(request):
    pid = request.match_info["pid"]
    job = request.app["provisions"].get(pid)
    if job is None:
        return web.Response(status=404, text="no such provision job")
    return render(request, "_provision.html", {"pid": pid, "job": job})


# -- server-sent events ----------------------------------------------------------
def _sse_chunk(name: str, data: str) -> bytes:
    out = [f"event: {name}"]
    out.extend(f"data: {line}" for line in data.split("\n"))
    out.append("")
    return ("\n".join(out) + "\n").encode("utf-8")


async def _sse_open(request):
    user = await current_user(request)
    if user is None:
        return web.Response(status=401, text="login required"), None
    resp = web.StreamResponse(status=200, headers={
        "Content-Type": "text/event-stream", "Cache-Control": "no-cache",
        "Connection": "keep-alive", "X-Accel-Buffering": "no"})
    await resp.prepare(request)
    return resp, request.app["bus"].subscribe()


async def events_stream(request):
    resp, queue = await _sse_open(request)
    if queue is None:
        return resp
    try:
        while True:
            event = await queue.get()
            name = event["name"]
            if name == "log":
                continue
            await resp.write(_sse_chunk(
                name.replace(".", "-"), json.dumps(event["data"])))
    except (asyncio.CancelledError, ConnectionResetError):
        pass
    finally:
        request.app["bus"].unsubscribe(queue)
    return resp


async def logs_stream(request):
    resp, queue = await _sse_open(request)
    if queue is None:
        return resp
    try:
        for line in request.app["logring"].lines(100):
            await resp.write(_sse_chunk(
                "log", f'<div class="log-line">{html.escape(line)}</div>'))
        while True:
            event = await queue.get()
            if event["name"] != "log":
                continue
            await resp.write(_sse_chunk(
                "log", '<div class="log-line">'
                f'{html.escape(event["data"].get("line", ""))}</div>'))
    except (asyncio.CancelledError, ConnectionResetError):
        pass
    finally:
        request.app["bus"].unsubscribe(queue)
    return resp
