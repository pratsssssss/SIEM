#!/bin/bash
# Creates the siem_detector OpenSearch user: it may search events, and write alert evidence, nothing else.
# Run as root with OpenSearch up. Safe to re-run: an existing password is kept.
# The password never appears in a command line, and is stored only for the detector user.
set -euo pipefail

SECRET_DIR=/home/linux/siem/config/detector
SECRET_FILE=$SECRET_DIR/opensearch-detector.json
API=https://127.0.0.1:9200
admin() { curl -sS --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl "$@"; }

id siem-detector >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux siem-detector
usermod -aG linux siem-detector
install -d -o root -g siem-detector -m 750 "$SECRET_DIR"

umask 077
BODY=$(mktemp /root/.siem/detector-user.XXXXXX)
trap 'rm -f "$BODY"' EXIT

if [ ! -s "$SECRET_FILE" ]; then
  python3 - "$SECRET_FILE" <<'PY'
import json, secrets, sys
json.dump({"user": "siem_detector", "password": secrets.token_urlsafe(32)}, open(sys.argv[1], "w"))
PY
fi
chown root:siem-detector "$SECRET_FILE"
chmod 640 "$SECRET_FILE"

admin -f -X PUT "$API/_plugins/_security/api/roles/siem_detector" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster:monitor/main", "cluster:monitor/health", "indices:data/write/bulk"],
  "index_permissions": [
    {"index_patterns": ["siem-windows-*", "siem-linux-*"], "allowed_actions": ["indices:data/read/search*"]},
    {"index_patterns": ["siem-alerts-*"], "allowed_actions": ["indices:data/write/index", "indices:data/write/bulk*", "indices:admin/create", "indices:admin/mapping/put"]}
  ]
}' >/dev/null

python3 - "$SECRET_FILE" "$BODY" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
json.dump({"password": s["password"], "backend_roles": [], "attributes": {"purpose": "detection engine"}}, open(sys.argv[2], "w"))
PY
admin -f -X PUT "$API/_plugins/_security/api/internalusers/siem_detector" -H 'Content-Type: application/json' --data-binary "@$BODY" >/dev/null

admin -f -X PUT "$API/_plugins/_security/api/rolesmapping/siem_detector" -H 'Content-Type: application/json' -d '{"users": ["siem_detector"]}' >/dev/null
echo "siem_detector ready"
