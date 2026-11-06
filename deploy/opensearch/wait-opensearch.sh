#!/bin/bash
# Gates service startup on the REST API answering over TLS. No credential is needed:
# 401 proves the API and the Security plugin are up.
for _ in {1..60}; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
    --cacert /etc/opensearch/root-ca.pem https://127.0.0.1:9200/ || true)
  case "$code" in
    200 | 401) exit 0 ;;
  esac
  sleep 2
done
echo "OpenSearch REST API did not answer" >&2
exit 1
