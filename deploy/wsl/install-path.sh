#!/bin/bash
# Installs the attack path service. Run as root in WSL from the repository root. Safe to re-run.
# The library is copied from the asset install, whose wheel passed its hash check there. The path database is left alone.
set -euo pipefail
# Paths that differ between machines, from config/wsl/site.env and site.local.env.
. deploy/wsl/site.sh
app=/opt/siem-path
config=/home/linux/siem/config
data=/home/linux/siem/data

id siem-path >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-path
getent group siem-path-admin >/dev/null || groupadd --system siem-path-admin
# The asset socket answers siem-analyst members. This service only ever asks who held an address.
usermod -aG linux,siem-analyst siem-path

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -r /opt/siem-asset/lib "$work/lib"
install -d -o root -g root -m 755 "$app"
rm -rf "$app/lib" "$app/app"
cp -r "$work/lib" "$app/lib"
install -d -o root -g root -m 755 "$app/app"
cp -r attackpath/siem_path "$app/app/"
find "$app" -name __pycache__ -prune -exec rm -rf {} +
find "$app" -type d -exec chmod 755 {} +
find "$app" -type f -exec chmod 644 {} +
find "$app/lib" -name '*.so*' -exec chmod 755 {} +
chown -R root:root "$app"

install -d -o root -g siem-path -m 750 "$config/path"
render 640 root siem-path "$config/path/path.yaml" config/wsl/path/path.yaml
install -o root -g root -m 644 /etc/opensearch/root-ca.pem "$config/path/opensearch-ca.pem"
install -o root -g root -m 644 config/opensearch/*.json "$config/opensearch/"
install -d -o siem-path -g siem-path -m 700 "$data/path"
render 644 root root /etc/systemd/system deploy/systemd/siem-path.service deploy/systemd/siem.target
install -o root -g root -m 755 deploy/wsl/siem-path.sh /usr/local/bin/siem-path
systemctl daemon-reload
echo "path service installed"
