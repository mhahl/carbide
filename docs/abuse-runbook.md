# Abuse-handling runbook

Your sensors invite attack traffic, and the Squid egress path (D3) lets
containers reach the web. That makes your server IP someone else's potential
exit node. This runbook is the operational side of that decision.

## Prevent

- Keep the shipped Squid restrictions: container-network ACL only, cloud
  metadata/link-local denies, CONNECT limited to 443, body caps. Review
  `squid/squid.conf` diffs before deploying changes.
- Keep nftables egress rules tight (transparent mode): proxy redirect for
  80/443, DNS only to the site resolver, drop everything else direct.
- Keep quotas small enough to matter: `[quotas]` blob/session caps bound how
  much damage one session can log or fetch.
- Never expose the server API port to the internet (VPN-only + firewall).
  Rotate a sensor token the moment its sensor is suspect
  (`[server] tokens`, restart server + that sensor).

## Detect

- Watch Squid volume per container IP: a sudden flood of CONNECTs or POSTs is
  someone using you as an exit. `squid_hits` is queryable per session.
- Watch abuse-mailbox complaints and blocklists for the server IP.
- Watch disk: blob store growth and Postgres size; eviction TTLs bound
  containers, logrotate bounds logs.

## Respond

1. Identify the affinity: container IP → `affinities` →
   `(sensor_id, attacker_ip)`.
2. Preserve evidence first: the session reports, snapshots, and Squid hits
   already exist — copy the relevant blobs aside before touching anything.
3. Stop the bleeding: stop the container
   (`podman stop <container_id>` keeps the filesystem for forensics) or
   shrink its egress (tighten Squid ACLs temporarily).
4. Remove the affinity only after the final archive is confirmed
   (eviction does this automatically; manual removal should run the same
   forensics capture first).
5. Reply to the abuse complaint with timestamps, your honeypot-operator
   status, and what you blocked. Keep the ticket with the session IDs.

## Know your line

Honeypot operation is research, but knowingly letting attacks relay through
your infrastructure can still create liability that varies by jurisdiction.
When in doubt, tighten egress (or disable Squid: `[squid] enabled = false`
stops the tailer; also close the proxy ports) and keep operating
observation-only. This document is operational guidance, not legal advice.
