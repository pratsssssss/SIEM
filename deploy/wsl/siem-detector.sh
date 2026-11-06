#!/bin/bash
# Runs the detection engine's command line with its own libraries. See docs/detection/detection-engine.md.
export PYTHONPATH=/opt/siem-detector/lib:/opt/siem-detector/app PYTHONDONTWRITEBYTECODE=1
export SIEM_RULES=/opt/siem-detector/rules SIEM_DETECTOR_CONFIG=/home/linux/siem/config/detector/detector.yaml
exec python3 -m siem_detector "$@"
