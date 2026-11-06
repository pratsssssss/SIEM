#!/bin/bash
# Gates service startup on the broker answering Kafka's own API.
# The tool must not inherit the broker's heap or GC log settings.
unset KAFKA_GC_LOG_OPTS
export KAFKA_HEAP_OPTS=-Xmx128m
for _ in {1..30}; do
  if timeout 15 /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server 127.0.0.1:9092 >/dev/null 2>&1; then
    exit 0
  fi
  sleep 2
done
echo "Kafka broker did not answer" >&2
exit 1
