#!/bin/bash
# Installs the SOC analyst dashboard. Run as root from the repository root. Safe to re-run.
# It creates no account: run siem-dashboard-admin create afterwards. The dashboard database and certificate are left alone.
# The YAML library is copied from the asset install, whose wheel passed its hash check there.
set -euo pipefail
app=/opt/siem-dashboard
config=/home/linux/siem/config
data=/home/linux/siem/data

# linux is only for passing through /home/linux. siem-analyst opens the local sockets and the health state.
# The SIEM detects group changes as high severity, so a re-install must not repeat one that is already in place.
id siem-dashboard >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux,siem-analyst siem-dashboard
[ "$(id -nG siem-dashboard | tr ' ' '\n' | sort | tr '\n' ' ')" = "linux siem-analyst siem-dashboard " ] || usermod -G linux,siem-analyst siem-dashboard

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -r /opt/siem-asset/lib "$work/lib"
install -d -o root -g root -m 755 "$app"
rm -rf "$app/lib" "$app/app" "$app/static"
cp -r "$work/lib" "$app/lib"
install -d -o root -g root -m 755 "$app/app"
cp -r dashboard/siem_dashboard "$app/app/"
cp -r dashboard/static "$app/static"
find "$app" -name __pycache__ -prune -exec rm -rf {} +
find "$app" -type d -exec chmod 755 {} +
find "$app" -type f -exec chmod 644 {} +
find "$app/lib" -name '*.so*' -exec chmod 755 {} +
chown -R root:root "$app"

install -d -o root -g siem-dashboard -m 750 "$config/dashboard"
install -o root -g siem-dashboard -m 640 config/wsl/dashboard/dashboard.yaml "$config/dashboard/dashboard.yaml"
install -o root -g root -m 644 /etc/opensearch/root-ca.pem "$config/dashboard/opensearch-ca.pem"
install -d -o siem-dashboard -g siem-dashboard -m 700 "$data/dashboard"

# A private certificate for this server. The key is readable by the service alone. An owner's own certificate can replace it.
tls=$config/dashboard/tls
install -d -o root -g siem-dashboard -m 750 "$tls"
if [ ! -s "$tls/dashboard.key" ]; then
  umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -keyout "$tls/dashboard.key" -out "$tls/dashboard.crt" \
    -subj '/CN=siem-dashboard' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -addext 'keyUsage=digitalSignature' -addext 'extendedKeyUsage=serverAuth' 2>/dev/null
  umask 022
fi
chown root:siem-dashboard "$tls/dashboard.key" "$tls/dashboard.crt"
chmod 640 "$tls/dashboard.key"
chmod 644 "$tls/dashboard.crt"

install -o root -g root -m 644 deploy/systemd/siem-dashboard.service deploy/systemd/siem.target /etc/systemd/system/
install -o root -g root -m 755 deploy/wsl/siem-dashboard.sh /usr/local/bin/siem-dashboard
install -o root -g root -m 750 deploy/wsl/siem-dashboard-admin.sh /usr/local/sbin/siem-dashboard-admin
systemctl daemon-reload
echo "dashboard installed"
