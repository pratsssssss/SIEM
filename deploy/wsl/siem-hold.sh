#!/bin/bash
# Holds a WSL session open while the stack runs. Exits when siem.target stops.
# WSL ends about 16 s after its last session, even with services running.
for _ in {1..60}; do
  systemctl --quiet is-active siem.target && break
  sleep 5
done
while systemctl --quiet is-active siem.target; do
  sleep 30
done
