#!/bin/bash
# Creates the SIEM topics. Safe to re-run. Run with Kafka up.
# Limits come from docs/operations/resource-budget.md. retention.bytes applies per partition.
set -euo pipefail

export LOG_DIR=${LOG_DIR:-/tmp}
TOPICS=/opt/kafka/bin/kafka-topics.sh
BOOTSTRAP=127.0.0.1:9092
RETENTION_MS=259200000 # 72 hours

create() { # name partitions retention-bytes segment-bytes
  "$TOPICS" --bootstrap-server "$BOOTSTRAP" --create --if-not-exists --topic "$1" \
    --partitions "$2" --replication-factor 1 \
    --config retention.ms="$RETENTION_MS" --config retention.bytes="$3" --config segment.bytes="$4"
}

create siem-raw-logs 3 1073741824 104857600
create siem-alerts 1 268435456 67108864
create siem-incidents 1 268435456 67108864
