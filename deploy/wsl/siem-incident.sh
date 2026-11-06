#!/bin/bash
# Runs the correlation service, or the analyst command line, with its own libraries.
# See docs/detection/incident-management.md.
export PYTHONPATH=/opt/siem-correlator/lib:/opt/siem-correlator/app PYTHONDONTWRITEBYTECODE=1
exec python3 -m siem_correlator "$@"
