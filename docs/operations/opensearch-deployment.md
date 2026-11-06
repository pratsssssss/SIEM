# OpenSearch Deployment

**Status:** Deployed in Phase 6 and validated. Results are in the Phase 6 validation. Decisions: [D18](../adr/0003-service-runtime.md) and [D19](../adr/0004-wsl-lifecycle-service-management.md).

## Version

| Item | Value |
|---|---|
| OpenSearch | 3.9.0, the newest published 3.x release on 2026-10-30. Lucene 10.5.1 |
| Java | Bundled Eclipse Adoptium 25.0.4.1. OpenSearch 3.6.1+ supports 21, 25 and 26 |
| Operating system | Ubuntu 24.04, listed as tested by OpenSearch |
| Package | `opensearch-3.9.0-linux-x64.deb` from `artifacts.opensearch.org` |
| Package state | Installed with `dpkg`, held with `apt-mark hold` |

The 3.9.1 and 3.10.0 artifacts returned HTTP 403, so they were not published. The 2.19.x line is a maintenance branch and was not chosen.

## Install procedure

The `.deb` is not itself signed. The project publishes a detached GPG signature and a SHA-512 file. `install-opensearch.sh` stops unless all three checks pass:

| Check | Expected |
|---|---|
| Key fingerprint | `A8B2 D9E0 4CD5 1FEF 6AA2 DB53 BA81 D999 8119 1457`, as published in the Debian install docs |
| Signature | Good, from that key |
| SHA-512 | Matches the published file |

1. Put these in an empty download directory, keeping it outside the VHDX so it does not grow:
   - `opensearch-3.9.0-linux-x64.deb`
   - The same name with `.sig` and `.sha512` added
   - `opensearch-release.pgp` from `artifacts.opensearch.org/publickeys/`
2. Run as root in Ubuntu: `bash deploy/opensearch/install-opensearch.sh verify <dir>`
3. Run as root in Ubuntu: `bash deploy/opensearch/install-opensearch.sh install <dir>`
4. Start the stack with `deploy/windows/siem-up.ps1`.

Always pass `-d Ubuntu-24.04` to `wsl.exe`, because `docker-desktop` is the WSL default on this host.

## Configuration

| Setting | Value | Why |
|---|---|---|
| `network.host` | `127.0.0.1` | Localhost only |
| `discovery.type` | `single-node` | One node |
| `cluster.default_number_of_replicas` | `0` | No second node to hold replicas, so health stays green |
| JVM heap | `-Xms1g -Xmx1g` in `/etc/opensearch/jvm.options` | Phase 5 budget |
| `bootstrap.memory_lock` | `true` | Keeps the heap out of swap. `mlockall` is confirmed true |
| `vm.swappiness` | `10` in `/etc/sysctl.d/90-siem.conf` | Reduced from 60 |
| `plugins.security.audit.type` | `internal_opensearch` | Records failed logins and security events |

Configuration comes from `deploy/opensearch/opensearch.yml`. The package's default `opensearch.yml` is kept at `/root/.siem/opensearch.yml.dist`.

## Paths

| Use | Location |
|---|---|
| Data | `/home/linux/siem/data/opensearch`, owned by `opensearch`, mode 750 |
| Logs | `/var/log/opensearch`, the package default |
| Configuration | `/etc/opensearch` |
| Program | `/usr/share/opensearch` |
| Secrets | `/root/.siem`, mode 700 |

The `opensearch` user is in the `linux` group so it can pass through `/home/linux`.

## Security

**The demo security configuration is not used.** It ships publicly known certificates and default accounts, so the installer sets `DISABLE_INSTALL_DEMO_CONFIG=true`.

| Item | Setting |
|---|---|
| REST API | TLS only, using a private CA. Plain HTTP fails |
| Certificates | Generated on the host, valid until 2028-10-29, with SANs `localhost` and `127.0.0.1` |
| Accounts | `admin` only. Demo accounts are rejected with 401 |
| CA key and admin key | `/root/.siem/pki`, root only |
| Node key | `/etc/opensearch/node-key.pem`, mode 600 |
| Audit log | `security-auditlog-*` indices |

**Admin password:** the installer generates a random password, which the owner should replace by rotation. The password is stored only in `/root/.siem/opensearch-admin.curl`, mode 600. It is a curl configuration file, so tools can read it with `-K` and it never appears in a command line. It is not in the repository.

Use it like this:

```bash
sudo curl --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl https://127.0.0.1:9200/
```

To change it, run `deploy/opensearch/rotate-admin-password.sh` as root in an interactive terminal with OpenSearch running. The script prompts twice with hidden input, and it refuses to run without a terminal. `admin` is a reserved account, so even `admin` gets 403 from the account API. The script uses the admin client certificate instead.

| Rotation step | On failure |
|---|---|
| Confirm the stored credential works | Stops, nothing changed |
| Reject empty, mismatched, short or control-character input, or the current password | Stops, nothing changed |
| Apply the new hash, then prove the new password from a temporary file | Restores the old hash, credential file unchanged |
| Replace the credential file and the seed `internal_users.yml`, each by atomic move | Reports the failure |
| Confirm the old password gets 401 | Reports the failure |

## Service management

- `opensearch.service` and the analyzer service are **disabled at boot**. Nothing starts at login.
- Start with `deploy/windows/siem-up.ps1`, which opens the hold session and starts `siem.target`.
- Stop with `deploy/windows/siem-down.ps1`, which stops services by name, confirms the process and ports are gone, then ends WSL.
- The drop-in is `deploy/opensearch/opensearch-siem.conf`.
- The drop-in raises the start timeout from 75 s to 180 s, because the health gate counts towards it.
- Startup waits on `wait-opensearch.sh`. It accepts 200 or 401, because 401 proves the API and Security plugin are up.

**Start limit:** deliberate starts count towards `StartLimitBurst`. A limit of 3 in 10 minutes blocked a normal start during testing, so it is now 6. If it is ever hit, run `systemctl reset-failed opensearch.service`. `siem-up.ps1` does this every time.

## Network

OpenSearch's Java socket shows as `[::ffff:127.0.0.1]`, not `127.0.0.1`. WSL does not forward this socket type, so **port 9200 cannot be reached from Windows**. That suits this design, because every OpenSearch client runs in WSL2. A Windows client would need a separate decision.

## Recovery

| Event | Action |
|---|---|
| Service will not start | `journalctl -u opensearch` and `/var/log/opensearch/siem-lab.log`, then `systemctl reset-failed opensearch.service` |
| WSL ended without a clean stop | Run `siem-up.ps1`, then check `_cluster/health`. OpenSearch replays its translog |
| Password lost | Read it as root from the credential file. If that file is damaged or wrong, the rotation script stops, so restore the file from an export or set a new hash with the admin certificate |
| Certificates near expiry | Before 2028-10-29, generate new ones from the CA and restart |
| Distro lost | Import the export below, then repeat the install |

**Recovery export:** `%USERPROFILE%\SIEM-Lab\backups\wsl\ubuntu-24.04-pre-opensearch-20261030.tar`. It was taken **before** OpenSearch was installed, so it holds no OpenSearch data, certificates or password. The later `ubuntu-24.04-pre-kafka-20261030.tar` does contain them, so it must be handled as sensitive.

## Expected log messages

| Message | Meaning |
|---|---|
| `Security not initialized` once at start | The health gate polled about 2 s before the plugin was ready |
| `Authentication finally failed` | Bad logins. Every one in Phase 6 came from the tests |
| `Failed to initialize LogType config index` | Security Analytics plugin at start. Not used here, and not investigated further |
| Performance Analyzer `FileNotFoundException` | Its configuration directory is not in the package. Its service is disabled and it is not used |
| `compliance salt` | Applies to field masking, which is not used |
| `StreamTransportService is not available` | ML Commons streaming, which is not used |
| SQL `Master key is a required config` | SQL data sources, which are not used |

## Known limits

- `securityadmin.sh -backup` connects with the admin certificate, then exits 255 with a deserialization error. It looks like a tool defect in 3.9.0, but this is unconfirmed. Applying configuration with `securityadmin.sh` was not tested.
- Index templates, ISM retention and audit protection came in Phase 8. See [Vector aggregator deployment](vector-aggregator-deployment.md).
- Nothing yet removes `security-auditlog-*` or `top_queries-*` indices, which are created daily.

_Internal test reports and planning records mentioned here are not published with Version 1._
