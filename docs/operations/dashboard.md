# SOC Analyst Dashboard

A self-hosted workspace over the whole SIEM: events, alerts, incidents, attack paths, assets, threat intelligence, pipeline health and audit history. It runs on the SIEM server, under its own unprivileged account. **Nothing in the SIEM depends on it.** Decisions are in [ADR-0017](../adr/0017-soc-dashboard.md), and results are in the acceptance report.

## How it fits

```
Browser
  | HTTPS, session cookie, CSRF token
  v
siem-dashboard, unprivileged, on loopback
  |-- static pages (no secrets)
  |-- /api/v1 --+-- OpenSearch: siem_dashboard, search only, named fields only
                +-- incident, asset, path sockets: a fixed list of actions
                +-- health state: read-only file, through Phase 16's own views
```

Kafka is never touched. Browsers reach only this service. OpenSearch and Kafka stay on loopback, and no credential reaches a browser.

## First-time setup

As root on the server, from the repository, with OpenSearch up:

```bash
bash deploy/wsl/install-dashboard.sh
bash deploy/opensearch/create-dashboard-user.sh
systemctl start siem-dashboard
siem-dashboard-admin create <name>
```

The last command asks for a password twice, with no echo. **No account exists until this is run,** and until then nothing opens. The install creates a system account `siem-dashboard`, and the SIEM correctly raises an alert and incident for that.

## The administrator account

This is a dashboard account. It has nothing to do with Linux `root`, or any other system account. Never use a system password here.

| Command, as root on the server | Does |
|---|---|
| `siem-dashboard-admin create <name>` | Creates the one account. Fails if one exists |
| `siem-dashboard-admin reset-password` | Replaces the password, and ends every session |
| `siem-dashboard-admin status` | Whether an account exists, whether sign-in is on, live sessions, locks |
| `siem-dashboard-admin revoke-sessions` | Ends every session |
| `siem-dashboard-admin disable`, `enable` | Refuses or allows all sign-in |
| `siem-dashboard-admin unlock` | Clears sign-in throttling |
| `siem-dashboard-admin remove` | Deletes the account. The audit trail stays |
| `siem-dashboard-admin verify-audit` | Checks the audit chain |

To script it, use `--password-stdin` and pipe from a protected source. A password is never accepted as an argument, so it stays out of shell history and process lists. It needs at least 14 characters.

The administrator can also change the password under **Settings**. That needs the current password, and it ends every other session.

**A lost password** is replaced with `reset-password`. There is no other route, by design.

## Sessions

| Setting | Value |
|---|---|
| Idle limit | 30 minutes |
| Absolute limit | 8 hours, whatever the activity |
| Cookie | `__Host-siem_session`: Secure, HttpOnly, SameSite=Strict |
| Stored as | SHA-256 of the token. Reading the database gives no live session |
| Rotated | A new token at every sign-in and password change |
| Throttling | 5 failures for one name in 15 minutes locks it for 15. 20 overall locks all sign-in |

A lock also stops the real administrator, so an attacker could deny sign-in. `unlock` clears it, as root.

## Reaching it

### A: this lab, Windows with WSL2

Open `https://localhost:8443/` in a browser on the Windows host. WSL forwards loopback ports to the Windows loopback only, so nothing else on the network can reach it. The certificate is private, so the browser warns. To stop the warning, trust the certificate, as an owner's decision:

```powershell
wsl -d Ubuntu-24.04 -u root -- cat /home/linux/siem/config/dashboard/tls/dashboard.crt > dashboard.crt
```

Then import `dashboard.crt` into **Trusted Root Certification Authorities** for the current user.

**From another device,** use an SSH tunnel to the Windows host, if SSH is set up there:

```bash
ssh -L 8443:127.0.0.1:8443 <user>@<windows-host>
```

This phase changes no Windows networking or firewall policy. A port proxy would expose the dashboard to the local network, and that is the owner's decision.

### B: a dedicated Linux server

The same files run there. Paths are all settings in `dashboard.yaml`, and only the service units and `/home/linux` layout need following. Any one of:

- **SSH tunnel:** keep loopback, and tunnel as above. This is the simplest and safest.
- **VPN:** set `require_loopback: false` and `listen.host` to the VPN address. Restrict the port with a firewall.
- **Reverse proxy:** keep loopback, and put nginx or Caddy in front with a real certificate. Pass the original `Host`, so that the same-origin check works.

**Never expose this directly to the internet.** A wildcard address is refused in any case. Replace `tls/dashboard.crt` and `dashboard.key` with a real certificate, keeping the key `640 root:siem-dashboard`. HSTS is sent automatically off loopback.

## Screens


| Screen | Shows | Changes |
|---|---|---|
| Overview | Security, operations, assets, intelligence and paths | None |
| Events | Bounded search over daily indices, and permitted fields | None |
| Alerts | Filters, verdicts, evidence and links | None. Alerts are never altered |
| Incidents | Every incident from the correlator | Status, notes |
| Investigations | Incidents in progress, opening the full workspace | As above |
| Attack Paths | Graph, table, timeline, evidence by edge | A note, kept apart from the engine's work |
| Assets | Inventory, history, relationships, software, services, identities | Mark a change reviewed |
| Threat Intelligence | Verdicts by indicator | None, and nothing triggers a lookup |
| Pipeline Health | Phase 16's states, lag, resources, history | None |
| Audit History | Sign-ins and changes, plus each service's trail | None |
| Settings | Account, session, password | Own password |

**Labels to rely on:**

| Label | Means |
|---|---|
| Unavailable | That section could not be read. This is never shown as zero |
| No stored alert | An incident none of whose alerts exist. These are the old test fixtures, or records past retention, and they stay out of security counts |
| Not checked | OpenSearch is out, so a record could not be checked |
| Possible asset | Phase 14's search on a host name. A name alone proves nothing |
| Correlated, not observed | The correlator's join. It is not an observation |
| Solid, dashed, dotted edge | Observed, inferred, or a rule's or analyst's interpretation |
| Expired or unavailable evidence | Past retention. This does not say the evidence was wrong |
| Changed evidence | Found, and different from what was recorded. This matters |
| No known threat | Nothing found in the sources that answered. It does **not** mean safe |

**Fixtures:** alerts have no marker separating controlled tests from other activity, so alerts raised by earlier phases' test runs and by installing this service do count. They were real detections of real activity.

## API

Base `/api/v1`. All JSON. Replies are `{"data": ..., "meta": {"request_id": ...}}` or `{"error": {"message", "code", "request_id"}}`. A `POST` needs the session cookie, `X-CSRF-Token` and `Content-Type: application/json`.

| Method and path | Purpose |
|---|---|
| `GET /auth/session` | Who is signed in, and the CSRF value |
| `POST /auth/login`, `/auth/logout`, `/auth/password` | Session |
| `GET /overview?range=` | All six summaries |
| `GET /search?q=` | Exact lookups, labelled by kind |
| `GET /events`, `/events/{index}/{id}` | Filters `host`, `dataset`, `category`, `type`, `outcome`, `level`, `code`, `action`, `user`, `process`, `source_ip`, `destination_ip`, `event_id`, `platform` |
| `GET /alerts`, `/alerts/{id}` | Filters `severity`, `rule`, `host`, `user`, `type`, `alert_id`, `source_ip` |
| `GET /incidents`, `/incidents/{id}`, `/incidents/{id}/audit` | `status`, `severity`, `include_unverified` |
| `POST /incidents/{id}/status` | `state`, `note` |
| `POST /incidents/{id}/notes` | `text` |
| `GET /investigations/alert/{id}` | The alert's linked view |
| `GET /assets`, `/assets/{id}`, `/assets/{id}/{software,services,users,history,relationships}` | `q`, `status`, `platform` |
| `GET /assets/changes`, `/assets/conflicts` | Review lists |
| `POST /assets/changes/{seq}/acknowledge` | `note` |
| `GET /attack-paths`, `/attack-paths/{id}`, `/attack-paths/{id}/evidence` | `tier`, `edge` |
| `POST /attack-paths/{id}/notes` | `text` |
| `GET /threat-intelligence` | `verdict` |
| `GET /health/{overview,components,lag,resources,failures,history,metrics,catalog}`, `/health/components/{name}`, `/health/metrics/{name}` | Phase 16's views |
| `GET /audit`, `/audit/verify` | Trails and chains |

**Limits:** `size` up to 100, `offset` up to 900, ranges `1h`, `6h`, `24h`, `7d`, `30d`, or `custom` under 30 days. 240 requests a minute per session. Bodies up to 16 KiB. OpenSearch searches stop after 5 seconds, and a partial result is refused.

**A section** is `{"status": "ok", "data": ...}`, `{"status": "unavailable", "reason": ...}` or `{"status": "missing"}`. One failing section leaves the rest of a page working.

## Security

| Threat | Control |
|---|---|
| Unauthenticated user | Every route needs a session. Anonymous callers learn only that they are signed out, and not whether an account exists |
| Stolen password | Throttling, an audit trail, and root can revoke sessions and reset. **There is no second factor** |
| Stolen cookie | HttpOnly, so scripts cannot read it. Short limits. Root can revoke it |
| CSRF | SameSite=Strict, a session-bound token, an origin check, and JSON only |
| XSS | All output goes through one function that sets text. No inline script is allowed by policy. Links from data are refused |
| Session fixation | A session is only ever created at sign-in, and a supplied cookie is ignored |
| SQL injection | Bound parameters everywhere |
| Query injection | Fixed query shapes. Input reaches only `term` values, and there is no free-text query |
| Path traversal | Static files come from a list made at start. An event index must match an exact pattern |
| Malicious event content | Treated as text. Rendered, never run |
| Malicious graph data | Text nodes only, and a bound on what is drawn |
| API abuse | Rate limits, size limits, a connection limit, and time limits |
| Request desynchronisation | A body left unread closes the connection |
| Brute force | scrypt, throttling by name and overall |
| Privilege escalation | No administrator group, no capabilities, no write access in OpenSearch |
| Backend compromise | Bounded by the account: no keys, no other logins, no service control. **It could still send analyst actions on the sockets,** as [ADR-0017](../adr/0017-soc-dashboard.md#d63-a-fixed-list-of-socket-actions) explains, and read what `siem_dashboard` can read |

The server never takes identity, role or actor from a request.

**Audit:** sign-ins, refusals, password changes and every change are in a hash-chained table that cannot be edited. Each row has the identity, action, target, time, outcome and request ID. Passwords, cookies, tokens and note text are never recorded there. The note itself stays in the owning service.

## Operations

It starts and stops with `siem-up.ps1` and `siem-down.ps1`. As root: `systemctl status siem-dashboard`.

**Backup:** `/home/linux/siem/data/dashboard/dashboard.db` with the service stopped, plus `/home/linux/siem/config/dashboard/`, which holds the certificate key and a service login, so keep it protected. Losing the database loses the dashboard's audit trail and the account: run `create` again.

## Failure and recovery

| Failure | Effect on the SIEM | Dashboard |
|---|---|---|
| Dashboard stopped or crashed | None | systemd restarts a crash. Sessions survive |
| OpenSearch down | Its own | Searches show unavailable. Assets, paths, health and incident records still work |
| Incident service down | Its own | Incident actions refuse, and are recorded as not done |
| Asset or path service down | Its own | Those sections show unavailable |
| Health monitor stopped | Its own | Shows the monitor is not current, as Phase 16 does |
| Bad configuration | None | The service will not start. Fix `dashboard.yaml` |

**Locked out:** `siem-dashboard-admin status`, then `unlock`, or `reset-password`.

## Known limits

See the acceptance report.

_Internal test reports and planning records mentioned here are not published with Version 1._
