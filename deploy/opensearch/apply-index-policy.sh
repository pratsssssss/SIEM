#!/bin/bash
# Applies index templates, retention and audit protection. Run as root with OpenSearch up. Safe to
# re-run. Existing policies are left in place, since changing one needs its sequence numbers.
set -euo pipefail
API=https://127.0.0.1:9200
CONFIG=${1:-/home/linux/siem/config/opensearch}
admin() { curl -sS --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl "$@"; }

admin -f -X PUT "$API/_index_template/siem-windows" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-windows-template.json" >/dev/null
admin -f -X PUT "$API/_index_template/siem-linux" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-linux-template.json" >/dev/null
admin -f -X PUT "$API/_index_template/siem-deadletter" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-deadletter-template.json" >/dev/null

admin -f -X PUT "$API/_index_template/siem-alerts" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-alerts-template.json" >/dev/null

admin -f -X PUT "$API/_index_template/siem-enrichment" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-enrichment-template.json" >/dev/null

admin -f -X PUT "$API/_index_template/siem-incidents" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-incidents-template.json" >/dev/null
admin -f -X PUT "$API/_index_template/siem-incident-audit" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-incident-audit-template.json" >/dev/null

for name in siem-attack-paths siem-attack-path-graph siem-attack-path-records; do
  admin -f -X PUT "$API/_index_template/$name" -H 'Content-Type: application/json' --data-binary "@$CONFIG/$name-template.json" >/dev/null
done
admin -f -X PUT "$API/_index_template/siem-health" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-health-template.json" >/dev/null
admin -f -X PUT "$API/_index_template/siem-assets" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-assets-template.json" >/dev/null
admin -f -X PUT "$API/_index_template/siem-asset-records" -H 'Content-Type: application/json' --data-binary "@$CONFIG/siem-asset-records-template.json" >/dev/null

policy() { # id file
  if [ "$(admin -o /dev/null -w '%{http_code}' "$API/_plugins/_ism/policies/$1")" = 200 ]; then
    echo "policy $1 kept"
  else
    admin -f -X PUT "$API/_plugins/_ism/policies/$1" -H 'Content-Type: application/json' --data-binary "@$CONFIG/$2" >/dev/null
    echo "policy $1 created"
  fi
}
policy siem-retention ism-siem-retention.json
policy siem-linux-retention ism-siem-linux-retention.json
policy siem-audit-protect ism-audit-protect.json
policy siem-alert-retention ism-siem-alert-retention.json
policy siem-enrichment-retention ism-siem-enrichment-retention.json
policy siem-incident-retention ism-siem-incident-retention.json
policy siem-asset-retention ism-siem-asset-retention.json
policy siem-attack-path-retention ism-siem-attack-path-retention.json
policy siem-health-retention ism-siem-health-retention.json
policy siem-health-metrics-retention ism-siem-health-metrics-retention.json

# A wildcard or _all delete must never remove evidence by accident.
admin -f -X PUT "$API/_cluster/settings" -H 'Content-Type: application/json' \
  -d '{"persistent":{"action.destructive_requires_name":true}}' >/dev/null

# Policies attach to new indices through ism_template, so existing audit indices are added here.
for index in $(admin "$API/_cat/indices/security-auditlog-*?h=index"); do
  admin -X POST "$API/_plugins/_ism/add/$index" -H 'Content-Type: application/json' -d '{"policy_id":"siem-audit-protect"}' >/dev/null || true
done
echo "index policy applied"
