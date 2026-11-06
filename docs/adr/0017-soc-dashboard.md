# ADR-0017: SOC Analyst Dashboard

| Field | Value |
|---|---|
| **Status** | Implemented on 2026-11-02, under the owner's Phase 17 brief. Subject to owner review, apart from D60, which the owner decided |
| **Decisions** | D60, D61, D62, D63, D64 |
| **Evidence** | Acceptance report, [operations and API](../operations/dashboard.md) |

**Phase number:** the owner's brief names this Phase 17, and that number held report generation, which is unbuilt. They became unscheduled, and no completed phase moved. See the [roadmap](../operations/deployment-roadmap.md).

## D60: One administrator, provisioned by root on the server

**Decided by the owner.** The dashboard has a single account, created by `siem-dashboard-admin` as root on the server. It has no default password, no setup page, no registration and no recovery route over the network. It is unrelated to any Linux account: `root` is refused as a name, and the code contains no route to system authentication.

**How it is built:** scrypt at 32 MiB per check, server-side sessions stored only as hashes, a `__Host-` cookie that is Secure, HttpOnly and SameSite=Strict, a session-bound CSRF token, 30-minute idle and 8-hour absolute limits, and throttling by name and overall.

**Later multi-user support:** identity comes from one function, `Auth.identity`, and returns a name and role. Replacing the single row and that function is the change. No route knows there is one user.

## D61: No new dependency

**Decision:** the backend is the Python standard library, plus the YAML package already on the host. The browser runs plain ES modules with no framework and no build step.

**Why:** this host has no Node and no web server, and the phase has a tight memory budget. A framework would add a build chain, a dependency tree to keep patched and a place for supply-chain risk, to save little in a page that mostly shows tables. Everything reaches the page through one function that only sets text.

**Cost:** more hand-written view code, and no component ecosystem. scrypt stands in for Argon2 because Argon2 would need a new compiled package.

**Why not a framework later:** nothing here prevents one. The API is the contract.

## D62: Reads through a field-limited role, changes through each service

**Decision:** `siem_dashboard` can only search, and only named fields. It holds no write, delete or administrative permission. State changes go through the service that owns the record, which validates them and writes its own audit.

**The field list is the control.** Real alerts hold command lines and script text in `evidence.matched_fields`, so that whole field is withheld, and the page explains so. The owner's brief allows raw content only if the existing security model does. It does not, so this phase does not widen it.

**Why this is a real limit:** an analyst cannot read a command line here, and must use the host or an administrator query. That is the safe default, and whether to change it is the owner's decision.

## D63: A fixed list of socket actions

**Decision:** the service joins `siem-analyst`, as `siem-path` does. That group's sockets also offer rule changes and replay. `backends.ALLOWED` lists what this service may send.

**This is enforced in this service's code, not by the operating system.** Someone who took over this process could call those other actions. It does not hold `siem-asset-admin` or `siem-path-admin`, so identity merges, ownership and rebuilds are refused by the services themselves.

**Options for the owner:** separate read and write sockets in the services would close this properly. That changes Phases 11, 12 and 14, so it was not done here. See also the Phase 15 open item on the asset socket.

**Consequence:** owner and criticality cannot be edited here, because that needs the administrator group. They stay with `siem-asset`.

## D64: Direct TLS on loopback, with no reverse proxy in the lab

**Decision:** the service terminates TLS itself on `127.0.0.1:8443`, with a private certificate made at install. WSL forwards that port to the Windows loopback, and to nothing else.

**Why:** no reverse proxy is installed, and adding one would serve one local connection. Windows networking and firewall policy are unchanged.

**A dedicated server** can place a reverse proxy in front, or set `require_loopback: false` with a specific address and a real certificate. A wildcard address is refused either way. HSTS is sent only off loopback, because it binds a whole host name, and on `localhost` it would force HTTPS on unrelated local services.

## Attribution

Incident, asset and path records name the OS account `siem-dashboard` as actor, because those services take identity from the kernel. They cannot be told a browser user's name, and that is the point of their design. The dashboard's own audit holds the signed-in name, the request ID, the action and the outcome. With one administrator the two line up by target and time. With several users, this would need a change to those services.

## Open items from earlier phases

| Item | Position |
|---|---|
| Dashboard read-only identity, Phases 14 to 16 | Decided here: `siem_dashboard` |
| Asset socket permissions, Phase 15 | Still open, and now applies to this service too. See D63 |
| Evidence expiry | Shown per edge, and never as a contradiction |
| Unverified multi-host behaviour | Still unverified |
| Phase 16 reruns | Not run, as they need the owner's approval |

## Correction on 2026-11-06

**Correction: every database read now holds the lock.** `Auth` shares one SQLite connection across request threads. Writes held the lock, but the session read in `identity()`, the account read in `admin()`, `status()` and both audit reads did not. The sqlite3 module reuses one prepared statement for the same SQL. So two requests checking sessions at once could reset each other's read, or be answered with each other's row.

The first did happen. A real browser was signed out part-way, because an empty read made a valid session look dead, and it was deleted. A parallel test reproduced it on its first run, with 36 of 60 requests refused. The second could in principle let one request act on another's session. All reads now hold the lock, which is re-entrant. Password hashing still runs outside it, so sign-in timing is unchanged. The parallel test has passed on all seven runs since.

_Internal test reports and planning records mentioned here are not published with Version 1._
