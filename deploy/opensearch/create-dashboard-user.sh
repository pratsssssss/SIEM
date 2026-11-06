#!/bin/bash
# Creates the siem_dashboard OpenSearch user. It searches named fields, and has no write, delete or administrative permission.
# Field level security is the control: whatever this service asks for, the server will not return a command line, script
# text, message body or file path. Alert evidence values are withheld for the same reason, as they can hold those.
# Run as root with OpenSearch up. Safe to re-run: an existing password is kept.
set -euo pipefail

SECRET_DIR=/home/linux/siem/config/dashboard
SECRET_FILE=$SECRET_DIR/opensearch-dashboard.json
API=https://127.0.0.1:9200
admin() { curl -sS --cacert /etc/opensearch/root-ca.pem -K /root/.siem/opensearch-admin.curl "$@"; }

id siem-dashboard >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --groups linux,siem-analyst siem-dashboard
install -d -o root -g siem-dashboard -m 750 "$SECRET_DIR"

umask 077
BODY=$(mktemp /root/.siem/dashboard-user.XXXXXX)
trap 'rm -f "$BODY"' EXIT

if [ ! -s "$SECRET_FILE" ]; then
  python3 - "$SECRET_FILE" <<'PY'
import json, secrets, sys
json.dump({"user": "siem_dashboard", "password": secrets.token_urlsafe(32)}, open(sys.argv[1], "w"))
PY
fi
chown root:siem-dashboard "$SECRET_FILE"
chmod 640 "$SECRET_FILE"

admin -f -X PUT "$API/_plugins/_security/api/roles/siem_dashboard" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster:monitor/main"],
  "index_permissions": [
    {"index_patterns": ["siem-windows-*", "siem-linux-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["@timestamp", "ecs.version", "event.id", "event.dataset", "event.code", "event.action", "event.outcome", "event.ingested", "event.created", "event.category", "event.type", "event.kind", "event.module", "event.provider", "log.level", "host.name", "host.hostname", "host.os.family", "host.os.type", "agent.name", "agent.type", "user.name", "user.domain", "user.id", "user.effective.name", "user.target.name", "user.target.domain", "group.name", "service.name", "process.name", "process.pid", "process.parent.name", "process.entity_id", "process.parent.entity_id", "source.ip", "source.port", "destination.ip", "destination.port", "network.protocol", "network.transport", "network.direction", "package.name", "package.version", "winlog.channel", "winlog.event_id", "winlog.record_id", "winlog.provider_name", "winlog.logon.type", "labels.attribution", "labels.protection", "labels.source_role", "siem.kafka.topic", "siem.kafka.partition", "siem.kafka.offset", "journald.exe_verified"]},
    {"index_patterns": ["siem-alerts-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["alert_id", "rule_id", "rule_name", "detection_type", "severity", "confidence", "timestamp", "detected_at", "description", "host", "user", "source_ip", "event_count", "source_event_ids", "raw_event_refs", "evidence_ref", "mitre.tactics", "mitre.techniques", "evidence.first_seen", "evidence.last_seen", "evidence.rule_fields"]},
    {"index_patterns": ["siem-enrichment-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["alert_id", "status", "enriched_at", "@timestamp", "events_available", "untrusted_notice", "summary.*", "indicators.type", "indicators.value", "indicators.verdict", "indicators.score", "indicators.independent_sources", "indicators.complete", "indicators.external_checked", "indicators.sources_answered", "indicators.sources_failed", "indicators.reasons"]},
    {"index_patterns": ["siem-incidents-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["incident_id", "title", "status", "severity", "confidence_level", "first_seen", "last_seen", "updated_at", "hosts", "ips", "alert_ids"]},
    {"index_patterns": ["siem-attack-paths-*"], "allowed_actions": ["indices:data/read/search*"],
     "fls": ["path_id", "seed.*", "title", "severity", "analyst_status", "tier", "conclusion", "gaps.*", "validation.*", "validated_at", "updated_ms", "path_at", "affected_assets.*", "evidence_state"]}
  ]
}' >/dev/null

python3 - "$SECRET_FILE" "$BODY" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
json.dump({"password": s["password"], "backend_roles": [], "attributes": {"purpose": "analyst dashboard"}}, open(sys.argv[2], "w"))
PY
admin -f -X PUT "$API/_plugins/_security/api/internalusers/siem_dashboard" -H 'Content-Type: application/json' --data-binary "@$BODY" >/dev/null

admin -f -X PUT "$API/_plugins/_security/api/rolesmapping/siem_dashboard" -H 'Content-Type: application/json' -d '{"users": ["siem_dashboard"]}' >/dev/null
echo "siem_dashboard ready"
