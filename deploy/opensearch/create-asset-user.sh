#!/bin/bash
# Creates the siem_asset OpenSearch user, and siem_asset_reader, a role for future readers that nobody holds yet.
# siem_asset reads named fields of events, alerts, enrichment and incidents, and writes only its own indices.
# Run as root with OpenSearch up. Safe to re-run: an existing password is kept.
# The password never appears in a command line, and is stored only for the asset user.
set -euo pipefail

SECRET_DIR=/home/linux/siem/config/asset
SECRET_FILE=$SECRET_DIR/opensearch-asset.json
API=https://127.0.0.1:9200
admin() { curl -sS --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl "$@"; }

id siem-asset >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-asset
usermod -aG linux siem-asset
install -d -o root -g siem-asset -m 750 "$SECRET_DIR"

umask 077
BODY=$(mktemp /root/.siem/asset-user.XXXXXX)
trap 'rm -f "$BODY"' EXIT

if [ ! -s "$SECRET_FILE" ]; then
  python3 - "$SECRET_FILE" <<'PY'
import json, secrets, sys
json.dump({"user": "siem_asset", "password": secrets.token_urlsafe(32)}, open(sys.argv[1], "w"))
PY
fi
chown root:siem-asset "$SECRET_FILE"
chmod 640 "$SECRET_FILE"

# Field level security: whatever this service asks for, the server will not return command lines, script text,
# file paths, raw events or free text.
admin -f -X PUT "$API/_plugins/_security/api/roles/siem_asset" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster:monitor/main", "indices:data/write/bulk"],
  "index_permissions": [
    {"index_patterns": ["siem-windows-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["@timestamp", "event.ingested", "event.code", "event.dataset", "host.name", "host.os.family", "user.name", "user.domain", "user.target.name", "group.name", "service.name", "process.name", "process.pe.product", "process.pe.company", "process.pe.file_version", "source.ip", "destination.ip", "destination.port", "network.direction"]},
    {"index_patterns": ["siem-linux-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["@timestamp", "event.ingested", "event.dataset", "event.action", "event.category", "event.outcome", "host.id", "host.name", "user.name", "user.target.name", "group.name", "service.name"]},
    {"index_patterns": ["siem-alerts-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["alert_id", "rule_name", "severity", "timestamp", "host", "user", "source_ip"]},
    {"index_patterns": ["siem-enrichment-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["alert_id", "indicators.type", "indicators.value", "indicators.verdict", "indicators.score"]},
    {"index_patterns": ["siem-incidents-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["incident_id", "title", "severity", "status", "hosts", "ips", "first_seen", "last_seen", "updated_at"]},
    {"index_patterns": ["siem-assets-current", "siem-asset-*"], "allowed_actions": ["indices:data/write/index", "indices:data/write/bulk*", "indices:admin/create", "indices:admin/auto_create", "indices:admin/mapping/put"]}
  ]
}' >/dev/null

# For detection rules and the dashboard, when they arrive. Read-only, and mapped to no one today.
admin -f -X PUT "$API/_plugins/_security/api/roles/siem_asset_reader" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": [],
  "index_permissions": [{"index_patterns": ["siem-assets-current", "siem-asset-relationships", "siem-asset-history-*"], "allowed_actions": ["indices:data/read/search*", "indices:data/read/get"]}]
}' >/dev/null

python3 - "$SECRET_FILE" "$BODY" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
json.dump({"password": s["password"], "backend_roles": [], "attributes": {"purpose": "asset inventory"}}, open(sys.argv[2], "w"))
PY
admin -f -X PUT "$API/_plugins/_security/api/internalusers/siem_asset" -H 'Content-Type: application/json' --data-binary "@$BODY" >/dev/null

admin -f -X PUT "$API/_plugins/_security/api/rolesmapping/siem_asset" -H 'Content-Type: application/json' -d '{"users": ["siem_asset"]}' >/dev/null
echo "siem_asset ready"
