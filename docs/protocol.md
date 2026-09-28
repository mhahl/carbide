# Sensor↔server protocol

Plain TCP, JSON objects, one per line (`carbide/common/protocol.py`).
Link security is the deployment's VPN; authentication is one token shared
by all sensors (each sensor keeps a unique `sensor_id` for affinity).

## Handshake

Sensor → `{"id","type":"hello","sensor_id","token"}`.
Server → `{"type":"reply","in_reply_to","ok":true}` or `ok:false` + close.
Bad or missing `sensor_id`s and wrong tokens are rejected; the sensor
retries with backoff.

## Requests

- `container_for {"attacker_ip"}` → `ok:true` plus
  `container_id, ssh_host, ssh_port, ssh_user, ssh_password, fresh`.
  The sensor SSH-proxies the attacker session to that endpoint.
- `ping` → `ok:true` (keepalive).

## Records (store-and-forward evidence)

Sensor → `{"id","type":"record","record_id","record":{...}}`.
Server → `ok:true` (applied or duplicate) or `ok:false` + error (sensor drops
the record as poison so one bad record cannot wedge the spool).

`record` always carries `record_id` (stable idempotency key), `kind`,
`sensor_id`, `session_id`, `at`. Kinds:

| kind | fields |
|---|---|
| `session_start` | `attacker_ip`, `username` |
| `session_container` | `container_id`, `fresh` |
| `session_end` | `reason` (triggers async forensics) |
| `auth_attempt` | `username`, `password`, `accepted`, `matched_list` |
| `transcript` | `channel`, `direction`, `stream`, `seq`, `data_b64` |
| `blob_meta` | `blob_sha`, `name`, `size` |
| `blob_chunk` | `blob_sha`, `name`, `seq`, `last`, `data_b64` |

Blob chunks reassemble server-side and verify the sha256 before storing;
a mismatch refuses that chunk. Records may arrive out of order or twice:
sessions auto-create on first sight, and `applied_records` dedupes.

The server never initiates messages; all sensor→server traffic above is
spooled to disk on the sensor before sending, forwarded in order, and removed
only after the server's ack.
