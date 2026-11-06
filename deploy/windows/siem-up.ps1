# Starts the SIEM stack in WSL2 and opens the hold session that keeps WSL running.
# Name the distro every time: docker-desktop is the WSL default on this host.
$Distro = 'Ubuntu-24.04'

Start-Process wsl.exe -WindowStyle Hidden -ArgumentList `
  '-d', $Distro, '--exec', '/home/linux/siem/scripts/siem-hold.sh'

$Units = @('opensearch.service', 'kafka.service', 'seal-verifier.service', 'vector.service', 'siem-detector.service', 'siem-enricher.service', 'siem-correlator.service', 'siem-asset.service', 'siem-path.service', 'siem-health.service', 'siem-health-watchdog.timer', 'siem-dashboard.service', 'siem-linux-agent.service')

# Clears any earlier start-limit failure. It prints an error when the unit is not loaded yet.
wsl.exe -d $Distro -u root --exec systemctl reset-failed @Units 2>$null
wsl.exe -d $Distro -u root --exec systemctl start siem.target
if ($LASTEXITCODE -ne 0) {
  Write-Error 'siem.target failed to start. Check journalctl -u opensearch and -u kafka.'
  exit 1
}
wsl.exe -d $Distro -u root --exec systemctl is-active @Units siem.target
exit $LASTEXITCODE
