# Analyst guide

Every investigation starts from one `sessions` row.

## Console first

The web console (URL + `admin` login from server `setup.sh`) covers the
flows below without SQL: **Sessions** reads a session cold end to end
(report, diff, files with one-click download and VirusTotal verdicts,
auth attempts with passwords, live-tailing transcript, Squid hits);
**Attackers** profiles each source IP (nmap open ports/services, all
its sessions and files with verdicts); **Compare** diffs two
sessions' container changes side by side with their snapshots;
**Snapshots** lists committed images; **Auth & creds** shows every
password guess plus the honeypot SSH credentials; **Podman** inspects
live containers (status, full `inspect`, live diff, per-file reads and
downloads); **Logs** tails the server log live; **Sensors** shows link
state; **Settings** manages the VirusTotal key and quota. Anything the
console can't express, drop to SQL (next section).

## Connecting

Postgres and the blob store live in the server stack — reach them through
compose (from `compose/server/` on the server host):

```sh
podman compose exec db psql -U carbide carbide          # SQL shell
podman compose exec server cat /var/lib/carbide/blobs/<2-hex>/<sha256>  # a blob
```

## Finding sessions

```sql
-- recent sessions with activity, newest first
SELECT session_id, sensor_id, attacker_ip, username, started_at, ended_at
FROM sessions ORDER BY started_at DESC NULLS LAST LIMIT 50;
```

## Reading a session cold

1. **Report**: `SELECT markdown FROM reports WHERE session_id = '...'` — the
   cumulative container diff, file notes, unified diffs, warnings.
2. **Transcript**: `SELECT channel, direction, stream, data FROM transcripts
   WHERE session_id = '...' ORDER BY id` — both directions, timestamped.
   `direction`: `in` (attacker→container), `out`, `op` (SFTP operation log).
3. **Files**: `SELECT name, blob_sha, size FROM session_files WHERE
   session_id = '...'`; fetch bytes from the blob store by hash
   (`blobs` maps sha256→path) and re-verify the hash. Name prefixes:
   `sftp-upload:`/`sftp-download:` (full container paths),
   `scp-upload:`/`scp-download:` (container destination resolved from the
   `scp -t/-f` target; bare basenames when no target was visible),
   `container:` (forensic diff content). `*-raw` holds unparsable
   remainders — always inspect those too. Only sensor-captured files
   (the `scp-*`/`sftp-*` evidence) are sent to VirusTotal;
   `container:` forensic captures stay local as evidence and show
   `unscanned`.
4. **Auth**: `SELECT username, password, accepted FROM auth_attempts WHERE
   session_id = '...' ORDER BY id`.
5. **Egress**: `SELECT at, method, url, status, bytes FROM squid_hits WHERE
   session_id = '...' ORDER BY id` — hostnames and sizes (TLS bodies are
   intentionally not decrypted). Any hit can be sent to VirusTotal
   with its Scan button; verdicts land in the VT column (pending rows
   complete on the next worker pass).

## Affinity and snapshots

- `affinities` maps `(sensor_id, attacker_ip)` to the current container.
  Reconnects from the same IP resume it; the per-session reports are
  cumulative, so diff consecutive reports for the incremental delta.
- `snapshots` lists committed images per affinity (retention-capped):
  `podman run -it <image> /bin/sh` to walk the exact filesystem, or
  `podman diff` between two snapshots.

## Blob store layout

`<blob_dir>/<first-2-hex>/<sha256>`, content-addressed: identical payloads
across sessions and sensors store once. `get_bytes` semantics (and the
`test_api` integrity check) re-hash on read — a mismatch means tampering or
disk corruption, investigate before trusting that blob.

## Caveats

- NAT sharing: all clients behind one public IP share an affinity container;
  transcripts stay attributable by session, container state does not.
- Oversized files and quota-dropped evidence are marked, never silent:
  look for `over_quota` on the session and `oversized`/`quota` notes.
- Deleted container files have no retrievable content (only the path);
  per-session snapshots may still hold them if the deletion came later.
- First-session reports are noisy by design: generated host keys, the honey
  password hash in `/etc/shadow`, and the proxy `SetEnv` line. Later
  sessions on the same affinity show the attacker's delta only.
- `gone before collection` means a tmpfs artifact (pid files, `/run`)
  vanished when the container stopped — routine, not evidence loss.
