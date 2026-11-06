#!/bin/bash
# Installs the detection engine. Run as root in WSL from the repository root. Safe to re-run.
# Usage: install-detector.sh <folder of wheels listed in detector/requirements.lock>
# Each wheel's hash is checked, then it is unpacked. Nothing from a wheel runs during installation.
set -euo pipefail
# Paths that differ between machines, from config/wsl/site.env and site.local.env.
. deploy/wsl/site.sh
wheels=$1
app=/opt/siem-detector
config=/home/linux/siem/config
data=/home/linux/siem/data

id siem-detector >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-detector
usermod -aG linux siem-detector

python3 - "$wheels" detector/requirements.lock <<'PY'
import hashlib, pathlib, sys
folder = pathlib.Path(sys.argv[1])
for line in open(sys.argv[2]):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    name, want = line.split()
    got = hashlib.sha256((folder / name).read_bytes()).hexdigest()
    if got != want:
        sys.exit(f'{name}: hash mismatch')
PY

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
grep -v '^#' detector/requirements.lock | awk 'NF{print $1}' | while read -r name; do
  python3 -I -m zipfile -e "$wheels/$name" "$work/lib/"
done

install -d -o root -g root -m 755 "$app"
rm -rf "$app/lib" "$app/app" "$app/rules"
cp -r "$work/lib" "$app/lib"
install -d -o root -g root -m 755 "$app/app"
cp -r detector/siem_detector "$app/app/"
cp -r rules "$app/rules"
find "$app" -name __pycache__ -prune -exec rm -rf {} +
find "$app" -type d -exec chmod 755 {} +
find "$app" -type f -exec chmod 644 {} +
find "$app/lib" -name '*.so*' -exec chmod 755 {} +
chown -R root:root "$app"

install -d -o root -g siem-detector -m 750 "$config/detector"
render 640 root siem-detector "$config/detector/detector.yaml" config/wsl/detector/detector.yaml
install -o root -g root -m 644 /etc/opensearch/root-ca.pem "$config/detector/opensearch-ca.pem"
install -o root -g root -m 644 config/opensearch/*.json "$config/opensearch/"
install -d -o siem-detector -g siem-detector -m 700 "$data/detector"

render 644 root root /etc/systemd/system deploy/systemd/siem-detector.service deploy/systemd/siem.target
install -o root -g root -m 755 deploy/wsl/siem-detector.sh /usr/local/bin/siem-detector
systemctl daemon-reload

# Compiles every rule as the service account, so a bad rule fails here and not at start.
runuser -u siem-detector -- /usr/local/bin/siem-detector validate
echo "detector installed"
