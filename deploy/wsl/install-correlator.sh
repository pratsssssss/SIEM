#!/bin/bash
# Installs the correlation service. Run as root in WSL from the repository root. Safe to re-run.
# Usage: install-correlator.sh <folder of wheels listed in correlator/requirements.lock>
# Each wheel's hash is checked, then it is unpacked. Nothing from a wheel runs during installation.
# The incident database is left alone.
set -euo pipefail
# Paths that differ between machines, from config/wsl/site.env and site.local.env.
. deploy/wsl/site.sh
wheels=$1
app=/opt/siem-correlator
config=/home/linux/siem/config
data=/home/linux/siem/data

id siem-correlator >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-correlator
usermod -aG linux siem-correlator
# Membership of this group is what lets a person work on incidents.
getent group siem-analyst >/dev/null || groupadd --system siem-analyst
usermod -aG siem-analyst linux

python3 - "$wheels" correlator/requirements.lock <<'PY'
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

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
grep -v '^#' correlator/requirements.lock | awk 'NF{print $1}' | while read -r name; do
  python3 -I -m zipfile -e "$wheels/$name" "$work/lib/"
done

install -d -o root -g root -m 755 "$app"
rm -rf "$app/lib" "$app/app"
cp -r "$work/lib" "$app/lib"
install -d -o root -g root -m 755 "$app/app"
cp -r correlator/siem_correlator "$app/app/"
find "$app" -name __pycache__ -prune -exec rm -rf {} +
find "$app" -type d -exec chmod 755 {} +
find "$app" -type f -exec chmod 644 {} +
find "$app/lib" -name '*.so*' -exec chmod 755 {} +
chown -R root:root "$app"

install -d -o root -g siem-correlator -m 750 "$config/correlator"
render 640 root siem-correlator "$config/correlator/correlator.yaml" config/wsl/correlator/correlator.yaml
install -o root -g siem-correlator -m 640 rules/correlation/rules.yml "$config/correlator/rules.yml"
install -o root -g root -m 644 /etc/opensearch/root-ca.pem "$config/correlator/opensearch-ca.pem"
install -o root -g root -m 644 config/opensearch/*.json "$config/opensearch/"
install -d -o siem-correlator -g siem-correlator -m 700 "$data/correlation"

render 644 root root /etc/systemd/system deploy/systemd/siem-correlator.service deploy/systemd/siem.target
install -o root -g root -m 755 deploy/wsl/siem-incident.sh /usr/local/bin/siem-incident
systemctl daemon-reload
echo "correlator installed"
