#!/bin/bash
# Installs the asset service. Run as root in WSL from the repository root. Safe to re-run.
# Usage: install-asset.sh [folder of wheels listed in inventory/requirements.lock]
# Each wheel's hash is checked, then it is unpacked. Nothing from a wheel runs during installation. With no
# folder, PyYAML is copied from the correlator install, which is always present and whose lock lists the same wheel and
# hash, checked at its installation.
# The asset database is left alone.
set -euo pipefail
# Paths that differ between machines, from config/wsl/site.env and site.local.env.
. deploy/wsl/site.sh
wheels=${1:-}
app=/opt/siem-asset
config=/home/linux/siem/config
data=/home/linux/siem/data

id siem-asset >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-asset
# The SIEM detects group changes as high severity, so a re-install must not repeat one that is already in place.
id -nG siem-asset | tr ' ' '\n' | grep -qx linux || usermod -aG linux siem-asset
getent group siem-analyst >/dev/null || groupadd --system siem-analyst
getent group siem-asset-admin >/dev/null || groupadd --system siem-asset-admin

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ -n "$wheels" ]; then
  python3 - "$wheels" inventory/requirements.lock <<'PY'
import hashlib, pathlib, sys
folder = pathlib.Path(sys.argv[1])
for line in open(sys.argv[2]):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    name, want = line.split()
    if hashlib.sha256((folder / name).read_bytes()).hexdigest() != want:
        sys.exit(f'{name}: hash mismatch')
PY
  grep -v '^#' inventory/requirements.lock | awk 'NF{print $1}' | while read -r name; do
    python3 -I -m zipfile -e "$wheels/$name" "$work/lib/"
  done
else
  lock=$(grep -v '^#' inventory/requirements.lock | awk 'NF')
  grep -qxF "$lock" correlator/requirements.lock || { echo 'correlator/requirements.lock does not list the same PyYAML wheel. Pass a wheel folder' >&2; exit 1; }
  install -d -m 755 "$work/lib"
  cp -r /opt/siem-correlator/lib/yaml /opt/siem-correlator/lib/_yaml /opt/siem-correlator/lib/pyyaml-6.0.3.dist-info "$work/lib/"
fi

install -d -o root -g root -m 755 "$app"
rm -rf "$app/lib" "$app/app"
cp -r "$work/lib" "$app/lib"
install -d -o root -g root -m 755 "$app/app"
cp -r inventory/siem_asset "$app/app/"
find "$app" -name __pycache__ -prune -exec rm -rf {} +
find "$app" -type d -exec chmod 755 {} +
find "$app" -type f -exec chmod 644 {} +
find "$app/lib" -name '*.so*' -exec chmod 755 {} +
chown -R root:root "$app"

install -d -o root -g siem-asset -m 750 "$config/asset"
render 640 root siem-asset "$config/asset/asset.yaml" config/wsl/asset/asset.yaml
install -o root -g root -m 644 /etc/opensearch/root-ca.pem "$config/asset/opensearch-ca.pem"
install -o root -g root -m 644 config/opensearch/*.json "$config/opensearch/"
install -d -o siem-asset -g siem-asset -m 700 "$data/asset"

render 644 root root /etc/systemd/system deploy/systemd/siem-asset.service deploy/systemd/siem.target
install -o root -g root -m 755 deploy/wsl/siem-asset.sh /usr/local/bin/siem-asset
systemctl daemon-reload
echo "asset service installed"
