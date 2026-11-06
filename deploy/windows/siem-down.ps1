# Stops SIEM services by name, in reverse start order, then ends WSL.
# Stopping siem.target alone returns before services finish, so it is never relied on.
# Add later services to the front of $Services.
$Distro = 'Ubuntu-24.04'
$Services = @('siem-dashboard.service', 'siem-health-watchdog.timer', 'siem-health.service', 'siem-path.service', 'siem-linux-health.timer', 'siem-linux-agent.service', 'siem-asset.service', 'siem-correlator.service', 'siem-enricher-feeds.timer', 'siem-enricher.service', 'siem-detector.service', 'siem-kafka-expiry-check.timer', 'siem-disk-guard.timer', 'vector.service', 'seal-verifier.service', 'kafka.service', 'opensearch.service')
$ServiceUsers = @('siem-dashboard', 'siem-health', 'siem-path', 'siem-linux-agent', 'siem-asset', 'siem-correlator', 'siem-enricher', 'siem-detector', 'vector', 'siem-verifier', 'kafka', 'opensearch')
$PortPattern = ':(9092|9093|9200|9300|9597|9599|9610|9611|9612|8443)\s'

wsl.exe -d $Distro -u root --exec systemctl stop @Services
if ($LASTEXITCODE -ne 0) {
  Write-Error 'A service failed to stop. WSL was left running.'
  exit 1
}

foreach ($Service in $Services) {
  wsl.exe -d $Distro -u root --exec systemctl --quiet is-active $Service
  if ($LASTEXITCODE -eq 0) {
    Write-Error "$Service is still active. WSL was left running."
    exit 1
  }
}

foreach ($ServiceUser in $ServiceUsers) {
  $null = wsl.exe -d $Distro -u root --exec pgrep -u $ServiceUser
  if ($LASTEXITCODE -eq 0) {
    Write-Error "A $ServiceUser process is still running. WSL was left running."
    exit 1
  }
}

$Sockets = wsl.exe -d $Distro -u root --exec ss -tln | Out-String
if ($LASTEXITCODE -ne 0 -or $Sockets -match $PortPattern) {
  Write-Error 'A SIEM port is still open, or sockets could not be read. WSL was left running.'
  exit 1
}

wsl.exe -d $Distro -u root --exec systemctl stop siem.target
wsl.exe --terminate $Distro
exit $LASTEXITCODE
