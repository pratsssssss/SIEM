#!/bin/bash
# Creates the siem_correlator OpenSearch user. It reads identity fields of events, plus alerts and
# enrichment, and writes only its own two index families.
# Run as root with OpenSearch up. Safe to re-run: an existing password is kept.
# The password never appears in a command line, and is stored only for the correlator user.
set -euo pipefail

SECRET_DIR=/home/linux/siem/config/correlator
SECRET_FILE=$SECRET_DIR/opensearch-correlator.json
API=https://127.0.0.1:9200
admin() { curl -sS --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl "$@"; }

id siem-correlator >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-correlator
usermod -aG linux siem-correlator
install -d -o root -g siem-correlator -m 750 "$SECRET_DIR"

umask 077
BODY=$(mktemp /root/.siem/correlator-user.XXXXXX)
trap 'rm -f "$BODY"' EXIT

if [ ! -s "$SECRET_FILE" ]; then
  python3 - "$SECRET_FILE" <<'PY'
import json, secrets, sys
json.dump({"user": "siem_correlator", "password": secrets.token_urlsafe(32)}, open(sys.argv[1], "w"))
PY
fi
chown root:siem-correlator "$SECRET_FILE"
chmod 640 "$SECRET_FILE"

# Field level security on events: the server, not only this service, keeps command lines and script text away from it.
admin -f -X PUT "$API/_plugins/_security/api/roles/siem_correlator" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster:monitor/main", "indices:data/write/bulk"],
  "index_permissions": [
    {"index_patterns": ["siem-windows-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["process.entity_id", "process.parent.entity_id", "process.name", "process.parent.name", "process.hash.sha256", "user.name", "user.domain", "user.id", "source.ip", "destination.ip", "dns.question.name"]},
    {"index_patterns": ["siem-alerts-*", "siem-enrichment-*"], "allowed_actions": ["indices:data/read/search*"]},
    {"index_patterns": ["siem-incidents-*", "siem-incident-audit-*"], "allowed_actions": ["indices:data/write/index", "indices:data/write/bulk*", "indices:admin/create", "indices:admin/auto_create", "indices:admin/mapping/put"]}
  ]
}' >/dev/null

python3 - "$SECRET_FILE" "$BODY" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
json.dump({"password": s["password"], "backend_roles": [], "attributes": {"purpose": "correlation"}}, open(sys.argv[2], "w"))
PY
admin -f -X PUT "$API/_plugins/_security/api/internalusers/siem_correlator" -H 'Content-Type: application/json' --data-binary "@$BODY" >/dev/null

admin -f -X PUT "$API/_plugins/_security/api/rolesmapping/siem_correlator" -H 'Content-Type: application/json' -d '{"users": ["siem_correlator"]}' >/dev/null
echo "siem_correlator ready"
