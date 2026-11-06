#!/bin/bash
# Creates the siem_enricher OpenSearch user: it may read events and alerts, and write its own results.
# Run as root with OpenSearch up. Safe to re-run: an existing password is kept.
# The password never appears in a command line, and is stored only for the enricher user.
set -euo pipefail

SECRET_DIR=/home/linux/siem/config/enricher
SECRET_FILE=$SECRET_DIR/opensearch-enricher.json
API=https://127.0.0.1:9200
admin() { curl -sS --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl "$@"; }

id siem-enricher >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-enricher
usermod -aG linux siem-enricher
install -d -o root -g siem-enricher -m 750 "$SECRET_DIR"

umask 077
BODY=$(mktemp /root/.siem/enricher-user.XXXXXX)
trap 'rm -f "$BODY"' EXIT

if [ ! -s "$SECRET_FILE" ]; then
  python3 - "$SECRET_FILE" <<'PY'
import json, secrets, sys
json.dump({"user": "siem_enricher", "password": secrets.token_urlsafe(32)}, open(sys.argv[1], "w"))
PY
fi
chown root:siem-enricher "$SECRET_FILE"
chmod 640 "$SECRET_FILE"

admin -f -X PUT "$API/_plugins/_security/api/roles/siem_enricher" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster:monitor/main", "cluster:monitor/health", "indices:data/write/bulk"],
  "index_permissions": [
    {"index_patterns": ["siem-windows-*", "siem-alerts-*"], "allowed_actions": ["indices:data/read/search*"]},
    {"index_patterns": ["siem-enrichment-*"], "allowed_actions": ["indices:data/write/index", "indices:data/write/bulk*", "indices:admin/create", "indices:admin/mapping/put"]}
  ]
}' >/dev/null

python3 - "$SECRET_FILE" "$BODY" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
json.dump({"password": s["password"], "backend_roles": [], "attributes": {"purpose": "enrichment"}}, open(sys.argv[2], "w"))
PY
admin -f -X PUT "$API/_plugins/_security/api/internalusers/siem_enricher" -H 'Content-Type: application/json' --data-binary "@$BODY" >/dev/null

admin -f -X PUT "$API/_plugins/_security/api/rolesmapping/siem_enricher" -H 'Content-Type: application/json' -d '{"users": ["siem_enricher"]}' >/dev/null
echo "siem_enricher ready"
