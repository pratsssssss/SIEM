#!/bin/bash
# Installs pinned Apache Kafka natively in WSL2 Ubuntu. Run as root.
#   install-kafka.sh verify  <download-dir>   Verify the archive only
#   install-kafka.sh install <download-dir>   Verify, install and format storage once
set -euo pipefail

VERSION=4.4.0
SCALA=2.13
JAVA_PKG_VERSION='17.0.20.1+1-1~24.04'
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
NAME=kafka_$SCALA-$VERSION
TGZ=$NAME.tgz
DATA_DIR=/home/linux/siem/data/kafka
CONFIG_DIR=/home/linux/siem/config/kafka
LOG_DIR=/var/log/kafka
HERE=$(dirname "$(readlink -f "$0")")
DEPLOY=$(dirname "$HERE")

MODE=${1:?usage: install-kafka.sh verify|install <download-dir>}
DL=${2:?usage: install-kafka.sh verify|install <download-dir>}

[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }

verify_archive() {
  local gh out want have signer
  gh=$(mktemp -d)
  chmod 700 "$gh"
  gpg --homedir "$gh" --quiet --import "$DL/KEYS" 2>/dev/null || true
  out=$(gpg --homedir "$gh" --status-fd 1 --verify "$DL/$TGZ.asc" "$DL/$TGZ" 2>/dev/null || true)
  echo "$out" | grep -q '^\[GNUPG:\] GOODSIG ' || { echo "Signature check failed" >&2; exit 1; }
  signer=$(echo "$out" | awk '/^\[GNUPG:\] VALIDSIG /{print $NF}')
  echo "signature: good, key $signer"
  want=$(sed -E 's/^[^:]*://' "$DL/$TGZ.sha512" | tr -d ' \r\n' | tr 'A-F' 'a-f')
  have=$(sha512sum "$DL/$TGZ" | cut -d' ' -f1)
  [ "$want" = "$have" ] || { echo "SHA-512 does not match" >&2; exit 1; }
  echo "sha512: good"
  rm -rf "$gh"
}

# Repository files may have CRLF endings on Windows.
put() { # source destination owner mode
  sed 's/\r$//' "$1" >"$2"
  chown "$3" "$2"
  chmod "$4" "$2"
}

verify_archive
[ "$MODE" = verify ] && exit 0
[ "$MODE" = install ] || { echo "Unknown mode: $MODE" >&2; exit 1; }

apt-get install -y -qq --no-install-recommends "openjdk-17-jre-headless=$JAVA_PKG_VERSION" >/dev/null
[ -x "$JAVA_HOME/bin/java" ] || { echo "Java 17 not found at $JAVA_HOME" >&2; exit 1; }

id kafka >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin kafka
usermod -aG linux kafka

if [ ! -d "/opt/$NAME" ]; then
  tar -xzf "$DL/$TGZ" -C /opt --no-same-owner
  chown -R root:root "/opt/$NAME"
fi
ln -sfn "/opt/$NAME" /opt/kafka

install -d -o kafka -g kafka -m 750 "$DATA_DIR" "$LOG_DIR"
install -d -o root -g kafka -m 750 "$CONFIG_DIR"
put "$HERE/server.properties" "$CONFIG_DIR/server.properties" root:kafka 640

install -d -m 755 /usr/local/lib/siem
put "$HERE/kafka.service" /etc/systemd/system/kafka.service root:root 644
put "$HERE/wait-kafka.sh" /usr/local/lib/siem/wait-kafka.sh root:root 755
put "$HERE/siem-kafka-tmpfiles.conf" /etc/tmpfiles.d/siem-kafka.conf root:root 644
put "$DEPLOY/systemd/siem.target" /etc/systemd/system/siem.target root:root 644
systemctl daemon-reload

# Formatting twice would discard the cluster's identity, so this only ever runs on empty storage.
if [ -e "$DATA_DIR/meta.properties" ]; then
  echo "storage already formatted, leaving it alone"
else
  [ -z "$(ls -A "$DATA_DIR")" ] || { echo "$DATA_DIR is not empty and has no meta.properties" >&2; exit 1; }
  [ -s "$CONFIG_DIR/cluster.id" ] ||
    JAVA_HOME=$JAVA_HOME LOG_DIR=$LOG_DIR /opt/kafka/bin/kafka-storage.sh random-uuid >"$CONFIG_DIR/cluster.id"
  chown root:kafka "$CONFIG_DIR/cluster.id"
  chmod 640 "$CONFIG_DIR/cluster.id"
  runuser -u kafka -- env JAVA_HOME="$JAVA_HOME" LOG_DIR="$LOG_DIR" \
    /opt/kafka/bin/kafka-storage.sh format --standalone -t "$(cat "$CONFIG_DIR/cluster.id")" \
    -c "$CONFIG_DIR/server.properties"
fi

echo "enabled at boot: $(systemctl is-enabled kafka.service || true)"
echo "installed $NAME"
