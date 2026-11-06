#!/bin/bash
# Runs the pipeline health service, or the read-only command line, with its own libraries.
# See docs/operations/pipeline-health.md.
export PYTHONPATH=/opt/siem-health/lib:/opt/siem-health/app PYTHONDONTWRITEBYTECODE=1
exec python3 -m siem_health "$@"
