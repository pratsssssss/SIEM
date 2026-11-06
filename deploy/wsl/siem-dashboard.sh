#!/bin/bash
# Runs the dashboard service with its own libraries. See docs/operations/dashboard.md.
export PYTHONPATH=/opt/siem-dashboard/lib:/opt/siem-dashboard/app PYTHONDONTWRITEBYTECODE=1
exec python3 -m siem_dashboard "$@"
