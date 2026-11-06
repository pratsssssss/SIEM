#!/bin/bash
# Installs the WSL2 Linux agent. Run as root in WSL from the repository root. Safe to re-run: existing keys,
# checkpoints and the disk buffer are left alone. Restart seal-verifier and vector afterwards.
# Keys are made here and written straight to their files. They never appear on a command line or in a log.
set -euo pipefail
# Paths that differ between machines, from config/wsl/site.env and site.local.env.
. deploy/wsl/site.sh
config=/home/linux/siem/config
data=/home/linux/siem/data

id siem-linux-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux,systemd-journal siem-linux-agent
usermod -aG linux,systemd-journal siem-linux-agent

install -d -o root -g siem-linux-agent -m 750 "$config/linux-agent"
install -d -o siem-linux-agent -g siem-linux-agent -m 700 "$data/linux-agent"

# k2 is this agent's own key (ADR-0008). The verifier allows it on Linux channels only.
python3 - "$config/linux-agent/field-keys.json" "$config/verifier/field-keys.json" <<'PY'
import json, os, secrets, sys
agent, verifier = sys.argv[1:3]
if not os.path.exists(agent):
    fd = os.open(agent, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(fd, 'w') as handle:
        json.dump({'k2_enc': secrets.token_hex(32), 'k2_mac': secrets.token_hex(32)}, handle)
keys = json.load(open(verifier))
wanted = json.load(open(agent))
if any(keys.get(k) != v for k, v in wanted.items()):
    keys.update(wanted)
    spare = verifier + '.new'
    fd = os.open(spare, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, 'w') as handle:
        json.dump(keys, handle)
    stat = os.stat(verifier)
    os.chown(spare, stat.st_uid, stat.st_gid)
    os.replace(spare, verifier)
PY
chown root:siem-linux-agent "$config/linux-agent/field-keys.json"
chmod 640 "$config/linux-agent/field-keys.json"

machine=$(cat /etc/machine-id)
# WSL takes the Windows computer name, so this host is named apart from the endpoint.
host=$(hostname | tr '[:upper:]' '[:lower:]')-wsl
umask 027
printf 'SIEM_LINUX_HOST=%s\nSIEM_LINUX_MACHINE=%s\n' "$host" "$machine" > "$config/linux-agent/agent.env"
chown root:siem-linux-agent "$config/linux-agent/agent.env"
install -o root -g siem-linux-agent -m 640 config/wsl/vector/vector-linux-agent.yaml "$config/linux-agent/vector-linux-agent.yaml"
install -d -o root -g root -m 755 /usr/local/lib/siem
install -o root -g root -m 755 deploy/wsl/siem-linux-health.py deploy/wsl/siem-linux-catchup.py /usr/local/lib/siem/
render 644 root root /etc/systemd/system deploy/systemd/siem-linux-agent.service deploy/systemd/siem-linux-health.service deploy/systemd/siem-linux-health.timer deploy/systemd/siem.target
install -o root -g root -m 644 config/opensearch/*.json "$config/opensearch/"
systemctl daemon-reload
echo "linux agent installed"
