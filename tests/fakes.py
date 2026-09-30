"""In-memory fakes mirroring Database and PodmanWrapper for unit tests."""
import datetime
import io
import tarfile


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class FakeDatabase:
    def __init__(self):
        self.sensors = {}
        self.affinities = {}
        self.sessions = {}
        self.attempts = []
        self.transcripts = []
        self.blobs = {}
        self.files = []
        self.diffs = []
        self.reports = {}
        self.snapshots = []
        self.squid = []
        self.applied = set()
        self.vt_scans = {}
        self.intel = {}

    async def note_sensor(self, sensor_id):
        self.sensors.setdefault(sensor_id, {"first": utcnow()})
        self.sensors[sensor_id]["last"] = utcnow()

    async def get_affinity(self, sensor_id, ip):
        return self.affinities.get((sensor_id, ip))

    async def get_affinity_by_container_ip(self, container_ip):
        for aff in self.affinities.values():
            if aff["container_ip"] == container_ip:
                return aff
        return None

    async def set_affinity(self, sensor_id, ip, container_id, ssh_port,
                           ssh_password, container_ip, created_at=None,
                           last_session_end=None, has_activity=False):
        self.affinities[(sensor_id, ip)] = {
            "sensor_id": sensor_id, "attacker_ip": ip,
            "container_id": container_id, "ssh_port": ssh_port,
            "ssh_password": ssh_password, "container_ip": container_ip,
            "has_activity": has_activity,
            "created_at": created_at or utcnow(),
            "last_session_end": last_session_end,
        }

    async def set_affinity_activity(self, sensor_id, ip, active):
        # Mirror UPDATE semantics: no row, no-op.
        if (sensor_id, ip) in self.affinities:
            self.affinities[(sensor_id, ip)]["has_activity"] = active

    async def touch_affinity_end(self, sensor_id, ip):
        if (sensor_id, ip) in self.affinities:
            self.affinities[(sensor_id, ip)][
                "last_session_end"] = utcnow()

    async def list_affinities(self):
        return list(self.affinities.values())

    async def delete_affinity(self, sensor_id, ip):
        self.affinities.pop((sensor_id, ip), None)

    async def ports_in_use(self):
        return {a["ssh_port"] for a in self.affinities.values()}

    async def ensure_session(self, session_id, sensor_id, ip):
        self.sessions.setdefault(session_id, {
            "session_id": session_id, "sensor_id": sensor_id,
            "attacker_ip": ip, "username": "", "container_id": "",
            "fresh": None, "over_quota": False, "started_at": None,
            "ended_at": None, "end_reason": ""})

    async def set_session_started(self, session_id, username, at, ip=None):
        update = {"username": username, "started_at": at}
        if ip is not None:
            update["attacker_ip"] = ip
        self.sessions[session_id].update(update)

    async def set_session_container(self, session_id, container_id, fresh):
        self.sessions[session_id].update(
            {"container_id": container_id, "fresh": fresh})

    async def set_session_end(self, session_id, at, reason):
        self.sessions[session_id].update(
            {"ended_at": at, "end_reason": reason})

    async def get_session(self, session_id):
        s = self.sessions.get(session_id)
        if not s:
            return None
        return (s["session_id"], s["sensor_id"], s["attacker_ip"],
                s["username"], s["container_id"], s["fresh"],
                s["over_quota"], s["started_at"], s["ended_at"],
                s["end_reason"])

    def _session_order(self, sensor_id, ip):
        rows = [s for s in self.sessions.values()
                if s["sensor_id"] == sensor_id and s["attacker_ip"] == ip]
        rows.sort(key=lambda s: s["started_at"] or
                  datetime.datetime.min.replace(
                      tzinfo=datetime.timezone.utc), reverse=True)
        return rows

    async def latest_open_session(self, sensor_id, ip):
        for s in self._session_order(sensor_id, ip):
            if s["ended_at"] is None:
                return (s["session_id"],)
        return None

    async def latest_session(self, sensor_id, ip):
        rows = self._session_order(sensor_id, ip)
        return (rows[0]["session_id"],) if rows else None

    async def add_auth_attempt(self, session_id, sensor_id, username,
                               password, accepted, matched, at):
        self.attempts.append((session_id, sensor_id, username, password,
                              accepted, matched, at))

    async def add_transcript(self, session_id, channel, direction, stream,
                             seq, data, at):
        self.transcripts.append((session_id, channel, direction, stream,
                                 seq, data, at))

    async def session_has_content(self, session_id):
        return (any(t[0] == session_id for t in self.transcripts) or
                any(f[0] == session_id for f in self.files))

    async def session_byte_count(self, session_id):
        total = sum(len(t[5]) for t in self.transcripts
                    if t[0] == session_id)
        return total + sum(f[3] for f in self.files if f[0] == session_id)

    async def set_session_over_quota(self, session_id):
        self.sessions[session_id]["over_quota"] = True

    async def claim_record(self, record_id):
        if record_id in self.applied:
            return False
        self.applied.add(record_id)
        return True

    async def add_blob(self, sha, path, size):
        self.blobs.setdefault(sha, (path, size))

    async def get_blob(self, sha):
        row = self.blobs.get(sha)
        return (sha, row[0], row[1]) if row else None

    async def add_session_file(self, session_id, name, sha, size, at):
        self.files.append((session_id, name, sha, size, at))

    async def add_diff_rows(self, session_id, rows):
        self.diffs.extend((session_id, p, k) for p, k in rows)

    async def get_diff_rows(self, session_id):
        return [(p, k) for s, p, k in self.diffs if s == session_id]

    async def save_report(self, session_id, markdown, js, at):
        self.reports[session_id] = (markdown, js, at)

    async def get_report(self, session_id):
        row = self.reports.get(session_id)
        return (row[0], row[1]) if row else None

    async def add_snapshot(self, sensor_id, ip, container_id, image):
        self.snapshots.append((image, utcnow(), sensor_id, ip,
                               container_id))

    async def list_snapshots(self, sensor_id, ip):
        return [(img, at) for img, at, s, i, _c in self.snapshots
                if s == sensor_id and i == ip]

    async def delete_snapshot(self, image):
        self.snapshots = [s for s in self.snapshots if s[0] != image]

    async def add_squid_hit(self, session_id, sensor_id, container_ip, at,
                            method, url, status, size, mime):
        self.squid.append((session_id, sensor_id, container_ip, at,
                           method, url, status, size, mime))

    # -- console reads -------------------------------------------------
    async def list_sensors(self):
        rows = [(sid, v.get("first"), v.get("last"))
                for sid, v in self.sensors.items()]
        rows.sort(key=lambda r: r[2] or datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc), reverse=True)
        return rows

    @staticmethod
    def _session_tuple(s):
        return (s["session_id"], s["sensor_id"], s["attacker_ip"],
                s["username"], s["container_id"], s["fresh"],
                s["over_quota"], s["started_at"], s["ended_at"],
                s["end_reason"])

    async def list_sessions(self, sensor_id=None, ip=None, open_only=False,
                            limit=100, offset=0):
        rows = [s for s in self.sessions.values()
                if (not sensor_id or s["sensor_id"] == sensor_id)
                and (not ip or s["attacker_ip"] == ip)
                and (not open_only or s["ended_at"] is None)]
        rows.sort(key=lambda s: (
            s["started_at"] is None, s["started_at"], s["session_id"]))
        rows.reverse()
        return [self._session_tuple(s)
                for s in rows[offset:offset + limit]]

    async def get_transcript(self, session_id, after_id=0, limit=500):
        out = []
        for idx, t in enumerate(self.transcripts):
            if t[0] == session_id and idx > after_id:
                out.append((idx, t[1], t[2], t[3], t[4], t[5], t[6]))
        return out[:limit]

    async def list_session_files(self, session_id):
        return [(idx, f[1], f[2], f[3], f[4])
                for idx, f in enumerate(self.files) if f[0] == session_id]

    async def list_auth_attempts(self, session_id=None, sensor_id=None,
                                 username=None, accepted=None,
                                 limit=200, offset=0):
        rows = [(idx,) + a for idx, a in enumerate(self.attempts)
                if (not session_id or a[0] == session_id)
                and (not sensor_id or a[1] == sensor_id)
                and (not username or a[2] == username)
                and (accepted is None or a[4] == accepted)]
        rows.reverse()
        return rows[offset:offset + limit]

    async def list_squid_hits(self, session_id=None, sensor_id=None,
                              limit=200, offset=0):
        rows = [(idx,) + h for idx, h in enumerate(self.squid)
                if (not session_id or h[0] == session_id)
                and (not sensor_id or h[1] == sensor_id)]
        rows.reverse()
        return rows[offset:offset + limit]

    async def list_snapshots_all(self, sensor_id=None, limit=200):
        rows = [(s, i, c, img, at)
                for img, at, s, i, c in self.snapshots
                if not sensor_id or s == sensor_id]
        rows.sort(key=lambda r: r[4], reverse=True)
        return rows[:limit]

    async def count_open_sessions(self):
        return sum(1 for s in self.sessions.values()
                   if s["ended_at"] is None)

    async def count_sessions_since(self, at):
        return sum(1 for s in self.sessions.values()
                   if s["started_at"] is not None and s["started_at"] >= at)

    async def count_affinities(self):
        return len(self.affinities)

    async def count_auth_since(self, at):
        return sum(1 for a in self.attempts if a[6] >= at)

    # -- console users / sessions --------------------------------------
    async def create_web_user(self, username, pw_hash):
        if not hasattr(self, "web_users"):
            self.web_users = {}
            self._web_seq = 0
        self._web_seq += 1
        self.web_users[self._web_seq] = {
            "id": self._web_seq, "username": username,
            "pw_hash": pw_hash, "created_at": utcnow(),
            "disabled": False}
        return self._web_seq

    async def get_web_user_by_name(self, username):
        for user in getattr(self, "web_users", {}).values():
            if user["username"] == username:
                return dict(user)
        return None

    async def get_web_user(self, user_id):
        user = getattr(self, "web_users", {}).get(user_id)
        return dict(user) if user else None

    async def list_web_users(self):
        return sorted((dict(u) for u in
                       getattr(self, "web_users", {}).values()),
                      key=lambda u: u["username"])

    async def set_web_user_disabled(self, user_id, disabled):
        if user_id in getattr(self, "web_users", {}):
            self.web_users[user_id]["disabled"] = disabled

    async def set_web_user_password(self, user_id, pw_hash):
        if user_id in getattr(self, "web_users", {}):
            self.web_users[user_id]["pw_hash"] = pw_hash

    async def create_web_session(self, token_sha, user_id, expires_at):
        if not hasattr(self, "web_sessions"):
            self.web_sessions = {}
        self.web_sessions[token_sha] = {"user_id": user_id,
                                        "expires_at": expires_at}

    async def get_web_session(self, token_sha):
        sess = getattr(self, "web_sessions", {}).get(token_sha)
        if not sess:
            return None
        user = await self.get_web_user(sess["user_id"])
        if not user:
            return None
        return (token_sha, sess["user_id"], sess["expires_at"],
                user["username"], user["disabled"])

    async def delete_web_session(self, token_sha):
        getattr(self, "web_sessions", {}).pop(token_sha, None)

    async def delete_expired_web_sessions(self):
        now = utcnow()
        for sha in [s for s, v in
                    getattr(self, "web_sessions", {}).items()
                    if v["expires_at"] < now]:
            del self.web_sessions[sha]

    # -- managed sensors ------------------------------------------------
    async def upsert_managed_sensor(self, sensor_id, ssh_host, ssh_port=22,
                                    ssh_user="", remote_dir="",
                                    listen_addr="0.0.0.0", listen_port=2222,
                                    server_host="", server_port=8440,
                                    auth_passwords="[]",
                                    accept_probability=0.05, notes=""):
        if not hasattr(self, "managed"):
            self.managed = {}
        self.managed[sensor_id] = {
            "sensor_id": sensor_id, "ssh_host": ssh_host,
            "ssh_port": ssh_port, "ssh_user": ssh_user,
            "remote_dir": remote_dir, "listen_addr": listen_addr,
            "listen_port": listen_port, "server_host": server_host,
            "server_port": server_port, "auth_passwords": auth_passwords,
            "accept_probability": accept_probability, "notes": notes,
            "updated_at": utcnow()}

    async def get_managed_sensor(self, sensor_id):
        row = getattr(self, "managed", {}).get(sensor_id)
        return dict(row) if row else None

    async def list_managed_sensors(self):
        return sorted((dict(r) for r in
                       getattr(self, "managed", {}).values()),
                      key=lambda r: r["sensor_id"])

    async def delete_managed_sensor(self, sensor_id):
        getattr(self, "managed", {}).pop(sensor_id, None)

    async def get_vt_scan(self, sha):
        row = self.vt_scans.get(sha)
        return dict(row) if row else None

    async def get_vt_scans(self, shas):
        return {s: dict(self.vt_scans[s]) for s in dict.fromkeys(shas)
                if s and s in self.vt_scans}

    async def save_vt_scan(self, sha, status, malicious=0, suspicious=0,
                           harmless=0, undetected=0, permalink="",
                           report_json="", analysis_id="", error=""):
        self.vt_scans[sha] = {
            "sha256": sha, "status": status, "malicious": malicious,
            "suspicious": suspicious, "harmless": harmless,
            "undetected": undetected, "permalink": permalink,
            "report_json": report_json, "analysis_id": analysis_id,
            "error": error, "scanned_at": utcnow(), "updated_at": utcnow()}

    async def get_ip_intel(self, ip):
        row = self.intel.get(ip)
        return dict(row) if row else None

    async def save_ip_intel(self, ip, rdns="", status="ok", open_ports="[]",
                            raw_xml="", error=""):
        self.intel[ip] = {
            "attacker_ip": ip, "rdns": rdns, "status": status,
            "open_ports": open_ports, "raw_xml": raw_xml, "error": error,
            "scanned_at": utcnow()}

    async def list_attackers(self, limit=200, offset=0):
        by_ip = {}
        for s in self.sessions.values():
            ip = s["attacker_ip"]
            if not ip:
                continue
            entry = by_ip.setdefault(ip, {"sessions": 0, "seen": None})
            entry["sessions"] += 1
            if s["started_at"] is not None and (
                    entry["seen"] is None
                    or s["started_at"] > entry["seen"]):
                entry["seen"] = s["started_at"]
        rows = []
        for ip, entry in by_ip.items():
            sids = {s["session_id"] for s in self.sessions.values()
                    if s["attacker_ip"] == ip}
            files = [f for f in self.files if f[0] in sids]
            mal = sum(1 for f in files
                      if (self.vt_scans.get(f[2]) or {}).get("malicious", 0)
                      > 0)
            intel = self.intel.get(ip, {}).get("status")
            rows.append((ip, entry["sessions"], entry["seen"], len(files),
                         mal, intel))
        floor = datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc)
        rows.sort(key=lambda r: r[2] or floor, reverse=True)
        return rows[offset:offset + limit]

    async def list_files_by_ip(self, ip, limit=500):
        sids = {s["session_id"] for s in self.sessions.values()
                if s["attacker_ip"] == ip}
        rows = []
        for idx, f in enumerate(self.files):
            if f[0] not in sids:
                continue
            vt = self.vt_scans.get(f[2]) or {}
            rows.append((idx, f[0], f[1], f[2], f[3], f[4],
                         vt.get("status"), vt.get("malicious"),
                         vt.get("suspicious")))
        rows.reverse()
        return rows[:limit]


class _FakeContainer:
    def __init__(self, cid, name):
        self.id = cid
        self.name = name
        self.labels = {"carbide": "affinity"}


class FakePodman:
    """In-memory containers with an editable file tree per container."""

    def __init__(self):
        self.containers = {}
        self.networks = set()
        self.images = []
        self._seq = 0

    # -- lifecycle ------------------------------------------------------
    def connect(self):
        pass

    def close(self):
        pass

    def ensure_network(self, name):
        if name:
            self.networks.add(name)

    def create_container(self, name, image, user, host_port, network,
                         environment, memory_mb, pids_limit):
        self._seq += 1
        cid = f"fake-c{self._seq:04d}"
        self.containers[cid] = {
            "name": name, "image": image, "status": "created",
            "port": host_port, "env": dict(environment),
            "files": {"/etc/motd": b"welcome\n",
                      "/home/honey/.profile": b"# profile\n"},
            "initial": None,
            "ip": f"10.89.0.{self._seq + 1}",
        }
        self.containers[cid]["initial"] = dict(
            self.containers[cid]["files"])
        return cid

    def _resolve(self, cid):
        if cid in self.containers:
            return cid
        for key, value in self.containers.items():
            if value["name"] == cid:
                return key
        raise KeyError(cid)

    def start(self, cid):
        self.containers[self._resolve(cid)]["status"] = "running"

    def stop(self, cid, timeout=10):
        key = self._resolve(cid)
        if self.containers[key]["status"] == "running":
            self.containers[key]["status"] = "exited"

    def remove(self, cid):
        self.containers.pop(self._resolve(cid), None)

    def exists(self, cid):
        try:
            self._resolve(cid)
            return True
        except KeyError:
            return False

    def status(self, cid):
        try:
            return self.containers[self._resolve(cid)]["status"]
        except KeyError:
            return "missing"

    def inspect(self, cid):
        key = self._resolve(cid)
        info = self.containers[key]
        return {"Id": key, "Name": info["name"],
                "State": {"Status": info["status"]},
                "Config": {"Image": info["image"]},
                "NetworkSettings": {
                    "Networks": {"carbide": {"IPAddress": info["ip"]}}}}

    def container_ip(self, cid):
        try:
            return self.containers[self._resolve(cid)]["ip"]
        except KeyError:
            return ""

    def list_carbide(self):
        return [_FakeContainer(cid, info["name"])
                for cid, info in self.containers.items()]

    def list_all_containers(self):
        return [{"id": cid, "name": info["name"],
                 "status": info["status"], "image": info["image"],
                 "created": "", "labels": {"carbide": "affinity"}}
                for cid, info in self.containers.items()]

    def list_images(self):
        out = []
        for idx, ref in enumerate(self.images):
            repo, _, tag = ref.partition(":")
            out.append({"id": f"img-{idx + 1}", "tags": [ref],
                        "repository": repo, "tag": tag or "latest",
                        "size": 0, "created": ""})
        return out

    def list_networks(self):
        return [{"name": name, "driver": "bridge", "subnets": []}
                for name in sorted(self.networks)]

    # -- file helpers for tests ------------------------------------------
    def write_file(self, cid, path, data: bytes):
        self.containers[self._resolve(cid)]["files"][path] = data

    def delete_file(self, cid, path):
        self.containers[self._resolve(cid)]["files"].pop(path, None)

    # -- forensics ----------------------------------------------------------
    def diff(self, cid):
        info = self.containers[self._resolve(cid)]
        before, after = info["initial"], info["files"]
        out = []
        for path in sorted(set(before) | set(after)):
            if path not in before:
                out.append({"Path": path, "Kind": 1})
            elif path not in after:
                out.append({"Path": path, "Kind": 2})
            elif before[path] != after[path]:
                out.append({"Path": path, "Kind": 0})
        return out

    def get_file(self, cid, path):
        if path.endswith("/"):
            from carbide.server.podman_wrap import IsDirError
            raise IsDirError(f"{path} is a directory")
        try:
            data = self.containers[self._resolve(cid)]["files"][path]
        except KeyError:
            from carbide.server.podman_wrap import PodmanError
            raise PodmanError(f"{path}: no such file")
        return data, {"isDir": False}

    def export_to(self, cid, dest_path):
        info = self.containers[self._resolve(cid)]
        with tarfile.open(dest_path, "w") as tar:
            for path, data in sorted(info["files"].items()):
                member = tarfile.TarInfo(path.lstrip("/"))
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))

    def commit(self, cid, image):
        self.images.append(image)
        return f"img-{len(self.images)}"

    def remove_image(self, image):
        if image in self.images:
            self.images.remove(image)
