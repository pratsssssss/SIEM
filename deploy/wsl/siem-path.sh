#!/bin/bash
# Runs the attack path service, or the analyst command line, with its own libraries.
# See docs/detection/attack-paths.md.
export PYTHONPATH=/opt/siem-path/lib:/opt/siem-path/app PYTHONDONTWRITEBYTECODE=1
exec python3 -m siem_path "$@"
