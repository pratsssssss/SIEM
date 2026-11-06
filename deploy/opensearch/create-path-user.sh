#!/bin/bash
# Creates the siem_path OpenSearch user. It reads named fields of events, alerts, enrichment and incidents, reads the
# current asset records, and writes only its own indices.
# Run as root with OpenSearch up. Safe to re-run: an existing password is kept.
# The password never appears in a command line, and is stored only for the path user.
set -euo pipefail

SECRET_DIR=/home/linux/siem/config/path
SECRET_FILE=$SECRET_DIR/opensearch-path.json
API=https://127.0.0.1:9200
admin() { curl -sS --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl "$@"; }

id siem-path >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-path
usermod -aG linux siem-path
install -d -o root -g siem-path -m 750 "$SECRET_DIR"

umask 077
BODY=$(mktemp /root/.siem/path-user.XXXXXX)
trap 'rm -f "$BODY"' EXIT

if [ ! -s "$SECRET_FILE" ]; then
  python3 - "$SECRET_FILE" <<'PY'
import json, secrets, sys
json.dump({"user": "siem_path", "password": secrets.token_urlsafe(32)}, open(sys.argv[1], "w"))
PY
fi
chown root:siem-path "$SECRET_FILE"
chmod 640 "$SECRET_FILE"

# Field level security: whatever this service asks for, the server will not return command lines, script text,
# message text, file paths, raw events or matched fields. It writes only its own indices.
admin -f -X PUT "$API/_plugins/_security/api/roles/siem_path" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster:monitor/main", "indices:data/write/bulk"],
  "index_permissions": [
    {"index_patterns": ["siem-windows-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["@timestamp", "event.id", "event.dataset", "event.code", "event.action", "event.outcome", "event.ingested", "host.name", "user.name", "user.domain", "user.id", "user.target.name", "user.target.domain", "group.name", "service.name", "process.name", "process.parent.name", "process.entity_id", "process.parent.entity_id", "source.ip", "destination.ip", "destination.port", "winlog.logon.type"]},
    {"index_patterns": ["siem-linux-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["@timestamp", "event.id", "event.dataset", "event.action", "event.outcome", "event.ingested", "host.name", "host.id", "user.name", "user.id", "user.effective.name", "user.target.name", "group.name", "service.name", "source.ip", "journald.exe_verified", "labels.attribution", "package.name"]},
    {"index_patterns": ["siem-alerts-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["alert_id", "rule_id", "rule_name", "severity", "confidence", "timestamp", "detected_at", "host", "user", "source_ip", "event_count", "raw_event_refs", "source_event_ids", "mitre.tactics", "mitre.techniques"]},
    {"index_patterns": ["siem-enrichment-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["doc_type", "alert_id", "status", "indicators.type", "indicators.value", "indicators.verdict", "indicators.score"]},
    {"index_patterns": ["siem-incidents-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["incident_id", "title", "severity", "status", "revision", "hosts", "users", "ips", "first_seen", "last_seen", "updated_at", "alert_ids", "rules.id", "rules.join", "uncertain"]},
    {"index_patterns": ["siem-assets-current"], "allowed_actions": ["indices:data/read/search*"]},
    {"index_patterns": ["siem-attack-paths-*", "siem-attack-path-*"], "allowed_actions": ["indices:data/write/index", "indices:data/write/bulk*", "indices:admin/create", "indices:admin/auto_create", "indices:admin/mapping/put"]}
  ]
}' >/dev/null

python3 - "$SECRET_FILE" "$BODY" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
json.dump({"password": s["password"], "backend_roles": [], "attributes": {"purpose": "attack paths"}}, open(sys.argv[2], "w"))
PY
admin -f -X PUT "$API/_plugins/_security/api/internalusers/siem_path" -H 'Content-Type: application/json' --data-binary "@$BODY" >/dev/null

admin -f -X PUT "$API/_plugins/_security/api/rolesmapping/siem_path" -H 'Content-Type: application/json' -d '{"users": ["siem_path"]}' >/dev/null
echo "siem_path ready"
