#!/bin/bash
# Installs the enrichment service. Run as root in WSL from the repository root. Safe to re-run.
# Usage: install-enricher.sh <folder of wheels listed in enricher/requirements.lock>
# Each wheel's hash is checked, then it is unpacked. Nothing from a wheel runs during installation.
# An existing provider key file and enrichment database are left alone.
set -euo pipefail
# Paths that differ between machines, from config/wsl/site.env and site.local.env.
. deploy/wsl/site.sh
wheels=$1
app=/opt/siem-enricher
config=/home/linux/siem/config
data=/home/linux/siem/data

id siem-enricher >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-enricher
usermod -aG linux siem-enricher

python3 - "$wheels" enricher/requirements.lock <<'PY'
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
grep -v '^#' enricher/requirements.lock | awk 'NF{print $1}' | while read -r name; do
  python3 -I -m zipfile -e "$wheels/$name" "$work/lib/"
done

install -d -o root -g root -m 755 "$app"
rm -rf "$app/lib" "$app/app"
cp -r "$work/lib" "$app/lib"
install -d -o root -g root -m 755 "$app/app"
cp -r enricher/siem_enricher "$app/app/"
find "$app" -name __pycache__ -prune -exec rm -rf {} +
find "$app" -type d -exec chmod 755 {} +
find "$app" -type f -exec chmod 644 {} +
find "$app/lib" -name '*.so*' -exec chmod 755 {} +
chown -R root:root "$app"

install -d -o root -g siem-enricher -m 750 "$config/enricher"
render 640 root siem-enricher "$config/enricher/enricher.yaml" config/wsl/enricher/enricher.yaml
install -o root -g root -m 644 /etc/opensearch/root-ca.pem "$config/enricher/opensearch-ca.pem"
install -o root -g root -m 644 config/opensearch/*.json "$config/opensearch/"
install -d -o siem-enricher -g siem-enricher -m 700 "$data/enrichment"
chown -R siem-enricher:siem-enricher "$data/enrichment"

render 644 root root /etc/systemd/system deploy/systemd/siem-enricher.service deploy/systemd/siem-enricher-feeds.service deploy/systemd/siem-enricher-feeds.timer deploy/systemd/siem.target
install -o root -g root -m 755 deploy/wsl/siem-enricher.sh /usr/local/bin/siem-enricher
systemctl daemon-reload
echo "enricher installed"
