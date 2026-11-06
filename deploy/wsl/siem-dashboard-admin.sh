#!/bin/bash
# Root-only administration of the dashboard account. Installed mode 750 root, in /usr/local/sbin.
export PYTHONPATH=/opt/siem-dashboard/lib:/opt/siem-dashboard/app PYTHONDONTWRITEBYTECODE=1
exec python3 -m siem_dashboard.admin "$@"
