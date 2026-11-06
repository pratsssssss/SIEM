#!/bin/bash
# Runs the enrichment command line with its own libraries. See docs/detection/enrichment.md.
export PYTHONPATH=/opt/siem-enricher/lib:/opt/siem-enricher/app PYTHONDONTWRITEBYTECODE=1
export SIEM_ENRICHER_CONFIG=/home/linux/siem/config/enricher/enricher.yaml
exec python3 -m siem_enricher "$@"
