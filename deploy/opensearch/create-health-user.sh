#!/bin/bash
# Creates the siem_health OpenSearch user. It reads cluster statistics and four named fields of events, alerts and
# enrichment, and writes only its own indices. It cannot read a command line or message, and cannot change anything else.
# Run as root with OpenSearch up. Safe to re-run: an existing password is kept.
# The password never appears in a command line, and is stored only for the health user.
set -euo pipefail

SECRET_DIR=/home/linux/siem/config/health
SECRET_FILE=$SECRET_DIR/opensearch-health.json
API=https://127.0.0.1:9200
admin() { curl -sS --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl "$@"; }

id siem-health >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-health
install -d -o root -g root -m 755 "$SECRET_DIR"

umask 077
BODY=$(mktemp /root/.siem/health-user.XXXXXX)
trap 'rm -f "$BODY"' EXIT

if [ ! -s "$SECRET_FILE" ]; then
  python3 - "$SECRET_FILE" <<'PY'
import json, secrets, sys
json.dump({"user": "siem_health", "password": secrets.token_urlsafe(32)}, open(sys.argv[1], "w"))
PY
fi
chown root:siem-health "$SECRET_FILE"
chmod 640 "$SECRET_FILE"

# Field level security: whatever this service asks for, the server returns timestamps and the dataset name only.
admin -f -X PUT "$API/_plugins/_security/api/roles/siem_health" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster:monitor/main", "cluster:monitor/health", "cluster:monitor/nodes/stats", "indices:data/write/bulk", "cluster:admin/opendistro/ism/managedindex/explain"],
  "index_permissions": [
    {"index_patterns": ["siem-windows-*", "siem-linux-*"], "allowed_actions": ["indices:data/read/search*", "indices:monitor/stats"], "fls": ["@timestamp", "event.ingested", "event.dataset"]},
    {"index_patterns": ["siem-alerts-*"], "allowed_actions": ["indices:data/read/search*", "indices:monitor/stats"], "fls": ["timestamp", "detected_at"]},
    {"index_patterns": ["siem-enrichment-*"], "allowed_actions": ["indices:data/read/search*"], "fls": ["@timestamp", "enriched_at"]},
    {"index_patterns": ["siem-deadletter-*"], "allowed_actions": ["indices:monitor/stats"]},
    {"index_patterns": ["siem-*"], "allowed_actions": ["cluster:admin/opendistro/ism/managedindex/explain", "indices:monitor/settings/get"]},
    {"index_patterns": ["siem-health-*"], "allowed_actions": ["indices:data/write/index", "indices:data/write/bulk*", "indices:admin/create", "indices:admin/auto_create", "indices:admin/mapping/put"]}
  ]
}' >/dev/null

python3 - "$SECRET_FILE" "$BODY" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
json.dump({"password": s["password"], "backend_roles": [], "attributes": {"purpose": "pipeline health"}}, open(sys.argv[2], "w"))
PY
admin -f -X PUT "$API/_plugins/_security/api/internalusers/siem_health" -H 'Content-Type: application/json' --data-binary "@$BODY" >/dev/null

admin -f -X PUT "$API/_plugins/_security/api/rolesmapping/siem_health" -H 'Content-Type: application/json' -d '{"users": ["siem_health"]}' >/dev/null
echo "siem_health ready"
