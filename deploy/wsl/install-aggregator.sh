#!/bin/bash
# Installs the seal verifier, Vector aggregator, monitors and their units. Run as root in WSL, from
# the repository root, with the verifier binaries in $1 and the Vector tarball at $2. Safe to re-run.
# Field keys arrive separately, from deploy/windows/install-vector-agent.ps1.
set -euo pipefail
# Paths that differ between machines, from config/wsl/site.env and site.local.env.
. deploy/wsl/site.sh
bin_dir=$1
tarball=$2
version=0.61.0
tarball_sha256=84a27c3ad6b772fdb05bb76ea01a31498bfc8f5e71f32cc78a0d96841f1aa827
config=/home/linux/siem/config
data=/home/linux/siem/data

echo "$tarball_sha256  $tarball" | sha256sum --check --quiet

getent group siem-verifier >/dev/null || groupadd --system siem-verifier
id siem-verifier >/dev/null 2>&1 || useradd --system --gid siem-verifier --no-create-home --shell /usr/sbin/nologin siem-verifier
id -nG siem-verifier | grep -qw linux || usermod -aG linux siem-verifier

install -d -o root -g root -m 755 /opt/seal-verifier
install -o root -g root -m 755 "$bin_dir/seal-verifier" /opt/seal-verifier/seal-verifier

if [ ! -x "/opt/vector-$version/bin/vector" ]; then
  mkdir -p "/opt/vector-$version"
  tar xzf "$tarball" -C "/opt/vector-$version" --strip-components=2
fi
ln -sfn "/opt/vector-$version" /opt/vector

install -d -o root -g siem-verifier -m 750 "$config/verifier"
install -d -o root -g vector -m 750 "$config/vector"
if [ ! -e "$config/verifier/tls" ]; then
  # CA keys exist only inside verifier-pki and are never written.
  work=$(mktemp -d)
  "$bin_dir/verifier-pki" -out "$work/tls"
  install -d -o root -g siem-verifier -m 750 "$config/verifier/tls"
  install -d -o root -g vector -m 750 "$config/vector/tls"
  install -o root -g siem-verifier -m 644 "$work/tls/verifier.crt" "$work/tls/vector-ca.crt" "$config/verifier/tls/"
  install -o root -g siem-verifier -m 640 "$work/tls/verifier.key" "$config/verifier/tls/"
  install -o root -g vector -m 644 "$work/tls/vector.crt" "$work/tls/verifier-ca.crt" "$config/vector/tls/"
  install -o root -g vector -m 640 "$work/tls/vector.key" "$config/vector/tls/"
  rm -rf "$work"
fi
# root-ca.pem is private to opensearch, and Vector needs its own copy to verify the certificate.
install -o root -g vector -m 644 /etc/opensearch/root-ca.pem "$config/vector/tls/opensearch-ca.pem"

install -o root -g vector -m 640 config/wsl/vector/vector-aggregator.yaml "$config/vector/vector-aggregator.yaml"
install -d -o root -g root -m 755 "$config/opensearch"
install -o root -g root -m 644 config/opensearch/*.json "$config/opensearch/"

install -d -o vector -g vector -m 750 "$data/vector"
install -d -o siem-verifier -g siem-verifier -m 700 "$data/verifier"
install -d -o linux -g linux -m 755 "$data/monitor"

install -d -o root -g root -m 755 /usr/local/lib/siem
install -o root -g root -m 755 deploy/wsl/siem-kafka-expiry-check.py deploy/wsl/siem-disk-guard.py /usr/local/lib/siem/
render 644 root root /etc/systemd/system deploy/systemd/vector.service deploy/systemd/seal-verifier.service deploy/systemd/siem.target \
  deploy/systemd/siem-kafka-expiry-check.service deploy/systemd/siem-kafka-expiry-check.timer \
  deploy/systemd/siem-disk-guard.service deploy/systemd/siem-disk-guard.timer
systemctl daemon-reload
echo "aggregator installed, $(/opt/vector/bin/vector --version)"
