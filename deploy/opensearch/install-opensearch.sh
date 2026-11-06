#!/bin/bash
# Installs pinned OpenSearch natively in WSL2 Ubuntu. Run as root.
#   install-opensearch.sh verify  <download-dir>   Verify the package only
#   install-opensearch.sh install <download-dir>   Verify, install and configure
# The admin password is generated here and is never printed or passed as an argument.
set -euo pipefail

VERSION=3.9.0
KEY_FPR=A8B2D9E04CD51FEF6AA2DB53BA81D99981191457 # Published in the OpenSearch Debian install docs
DATA_DIR=/home/linux/siem/data/opensearch
ETC=/etc/opensearch
SECRETS=/root/.siem
PKI=$SECRETS/pki
CRED=$SECRETS/opensearch-admin.curl
HOME_OS=/usr/share/opensearch
HERE=$(dirname "$(readlink -f "$0")")
DEPLOY=$(dirname "$HERE")

MODE=${1:?usage: install-opensearch.sh verify|install <download-dir>}
DL=${2:?usage: install-opensearch.sh verify|install <download-dir>}
DEB=opensearch-$VERSION-linux-x64.deb

[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }
umask 077

verify_package() {
  local gh out
  gh=$(mktemp -d)
  gpg --homedir "$gh" --quiet --import "$DL/opensearch-release.pgp" 2>/dev/null
  gpg --homedir "$gh" --with-colons --fingerprint | grep -q "^fpr:.*:$KEY_FPR:$" ||
    { echo "Key fingerprint does not match" >&2; exit 1; }
  echo "key fingerprint: $KEY_FPR"
  out=$(gpg --homedir "$gh" --status-fd 1 --verify "$DL/$DEB.sig" "$DL/$DEB" 2>/dev/null || true)
  echo "$out" | grep -q '^\[GNUPG:\] GOODSIG ' || { echo "Signature check failed" >&2; exit 1; }
  echo "$out" | grep '^\[GNUPG:\] VALIDSIG ' | grep -q " $KEY_FPR$" ||
    { echo "Signature is not from the expected key" >&2; exit 1; }
  echo "signature: good"
  (cd "$DL" && sha512sum --quiet -c "$DEB.sha512")
  echo "sha512: good"
  rm -rf "$gh"
}

# Repository files may have CRLF endings on Windows.
put() { # source destination owner mode
  sed 's/\r$//' "$1" >"$2"
  chown "$3" "$2"
  chmod "$4" "$2"
}

make_certificates() {
  [ -f "$PKI/root-ca.pem" ] && return
  install -d -m 700 "$SECRETS" "$PKI"
  local base="/O=SIEMLab/OU=OpenSearch"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PKI/root-ca-key.pem" 2>/dev/null
  openssl req -new -x509 -sha256 -key "$PKI/root-ca-key.pem" -subj "$base/CN=siem-lab-root-ca" \
    -days 730 -out "$PKI/root-ca.pem"
  local name cn
  for name in admin node; do
    cn=siem-admin
    [ "$name" = node ] && cn=localhost
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PKI/$name-key.pem" 2>/dev/null
    openssl req -new -key "$PKI/$name-key.pem" -subj "$base/CN=$cn" -out "$PKI/$name.csr"
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$PKI/$name.ext"
    openssl x509 -req -in "$PKI/$name.csr" -CA "$PKI/root-ca.pem" -CAkey "$PKI/root-ca-key.pem" \
      -CAcreateserial -sha256 -days 730 -extfile "$PKI/$name.ext" -out "$PKI/$name.pem" 2>/dev/null
  done
  rm -f "$PKI"/*.csr "$PKI"/*.ext
}

write_admin_user() {
  [ -f "$CRED" ] && { echo "admin credential already exists, keeping it"; return; }
  local hash
  SIEM_OS_PW=$(openssl rand -base64 33 | tr '+/' '-_')
  export SIEM_OS_PW
  hash=$(OPENSEARCH_JAVA_HOME=$HOME_OS/jdk \
    bash "$HOME_OS/plugins/opensearch-security/tools/hash.sh" -env SIEM_OS_PW 2>/dev/null | grep -E '^\$2[aby]\$' || true)
  [ -n "$hash" ] || { unset SIEM_OS_PW; echo "Password hashing failed" >&2; exit 1; }
  cp --update=none "$ETC/opensearch-security/internal_users.yml" "$SECRETS/internal_users.yml.dist"
  # Only the admin account exists. No demo users are carried over.
  printf -- '---\n_meta:\n  type: "internalusers"\n  config_version: 2\n\nadmin:\n  hash: "%s"\n  reserved: true\n  backend_roles:\n  - "admin"\n  description: "SIEM administrator"\n' \
    "$hash" >"$ETC/opensearch-security/internal_users.yml"
  chown opensearch:opensearch "$ETC/opensearch-security/internal_users.yml"
  chmod 600 "$ETC/opensearch-security/internal_users.yml"
  printf 'user = "admin:%s"\n' "$SIEM_OS_PW" >"$CRED"
  chmod 600 "$CRED"
  unset SIEM_OS_PW
}

verify_package
[ "$MODE" = verify ] && exit 0
[ "$MODE" = install ] || { echo "Unknown mode: $MODE" >&2; exit 1; }

command -v opensearch >/dev/null && { echo "Unexpected opensearch on PATH" >&2; exit 1; }
if ! dpkg -s opensearch >/dev/null 2>&1; then
  DISABLE_INSTALL_DEMO_CONFIG=true dpkg -i "$DL/$DEB"
fi
apt-mark hold opensearch
[ "$(dpkg-query -W -f='${Version}' opensearch)" = "$VERSION" ] || { echo "Wrong version installed" >&2; exit 1; }

usermod -aG linux opensearch
install -d -o opensearch -g opensearch -m 750 "$DATA_DIR"

make_certificates
rm -f "$ETC"/*.pem
install -o opensearch -g opensearch -m 600 "$PKI/root-ca.pem" "$ETC/root-ca.pem"
install -o opensearch -g opensearch -m 600 "$PKI/node.pem" "$ETC/node.pem"
install -o opensearch -g opensearch -m 600 "$PKI/node-key.pem" "$ETC/node-key.pem"

write_admin_user

cp --update=none "$ETC/opensearch.yml" "$SECRETS/opensearch.yml.dist"
put "$HERE/opensearch.yml" "$ETC/opensearch.yml" opensearch:opensearch 640
sed -i -E 's/^-Xms.*/-Xms1g/; s/^-Xmx.*/-Xmx1g/' "$ETC/jvm.options"

install -d -m 755 /etc/systemd/system/opensearch.service.d /usr/local/lib/siem
put "$HERE/opensearch-siem.conf" /etc/systemd/system/opensearch.service.d/siem.conf root:root 644
put "$HERE/wait-opensearch.sh" /usr/local/lib/siem/wait-opensearch.sh root:root 755
put "$DEPLOY/systemd/siem.target" /etc/systemd/system/siem.target root:root 644
put "$DEPLOY/wsl/siem-hold.sh" /home/linux/siem/scripts/siem-hold.sh linux:linux 750
printf 'vm.swappiness=10\n' >/etc/sysctl.d/90-siem.conf
chmod 644 /etc/sysctl.d/90-siem.conf
sysctl -q -p /etc/sysctl.d/90-siem.conf
systemctl daemon-reload

echo "enabled at boot: $(systemctl is-enabled opensearch.service || true)"
echo "installed $VERSION"
