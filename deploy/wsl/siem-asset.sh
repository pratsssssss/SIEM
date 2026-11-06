#!/bin/bash
# Runs the asset service, or the analyst command line, with its own libraries.
# See docs/detection/asset-inventory.md.
export PYTHONPATH=/opt/siem-asset/lib:/opt/siem-asset/app PYTHONDONTWRITEBYTECODE=1
exec python3 -m siem_asset "$@"
