#!/bin/bash
# Installs the pipeline health service. Run as root in WSL from the repository root. Safe to re-run.
# Each monitored service gets one status folder that it alone can write and only this service can read, so this
# service needs no access to any other service's private directory.
# The libraries are copied from the correlator install, whose wheels passed their hash checks there. The health database is left alone.
set -euo pipefail
# Paths that differ between machines, from config/wsl/site.env and site.local.env.
. deploy/wsl/site.sh
app=/opt/siem-health
config=/home/linux/siem/config
data=/home/linux/siem/data
status=$data/status

# Group linux only lets it pass through /home/linux, as for every service here. It is not in siem-analyst or systemd-journal.
id siem-health >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-health
# The SIEM detects group changes as high severity, so a re-install must not repeat one that is already in place.
[ "$(id -nG siem-health | tr ' ' '\n' | sort | tr '\n' ' ')" = "linux siem-health " ] || usermod -G linux siem-health

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -r /opt/siem-correlator/lib "$work/lib"
install -d -o root -g root -m 755 "$app"
rm -rf "$app/lib" "$app/app"
cp -r "$work/lib" "$app/lib"
install -d -o root -g root -m 755 "$app/app"
cp -r health/siem_health "$app/app/"
find "$app" -name __pycache__ -prune -exec rm -rf {} +
find "$app" -type d -exec chmod 755 {} +
find "$app" -type f -exec chmod 644 {} +
find "$app/lib" -name '*.so*' -exec chmod 755 {} +
chown -R root:root "$app"

# Status folders: owner writes, siem-health reads, nobody else enters.
install -d -o root -g root -m 755 "$status"
for pair in detector:siem-detector enricher:siem-enricher correlator:siem-correlator asset:siem-asset path:siem-path linux-agent:siem-linux-agent health-watchdog:siem-health; do
  install -d -o "${pair#*:}" -g siem-health -m 2750 "$status/${pair%%:*}"
done

# Analysts run the read-only command, which needs the settings and the state file. The login stays 640 in create-health-user.sh.
install -d -o root -g root -m 755 "$config/health"
render 644 root root "$config/health/health.yaml" config/wsl/health/health.yaml
install -o root -g root -m 644 /etc/opensearch/root-ca.pem "$config/health/opensearch-ca.pem"
install -o root -g root -m 644 config/opensearch/*.json "$config/opensearch/"
install -d -o siem-health -g siem-analyst -m 2750 "$data/health"
render 644 root root /etc/systemd/system deploy/systemd/siem-health.service deploy/systemd/siem-health-watchdog.service deploy/systemd/siem-health-watchdog.timer deploy/systemd/siem.target
install -o root -g root -m 755 deploy/wsl/siem-health.sh /usr/local/bin/siem-health
systemctl daemon-reload
echo "health service installed"
