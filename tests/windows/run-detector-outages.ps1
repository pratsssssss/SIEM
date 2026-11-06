# Live outages with the detector running: Kafka, OpenSearch, and a killed detector. Creates a harmless
# scheduled task to give the detector something to report, and removes it. Results go to -Out.
param([Parameter(Mandatory)] [string] $Out)
$Repo = Split-Path (Split-Path $PSScriptRoot)
$Distro = 'Ubuntu-24.04'
$Probe = '/mnt/c' + (($Repo.Substring(2) -replace '\\', '/')) + '/tests/detection/detector_probe.py'
function Note([string] $Text) { Add-Content -LiteralPath $Out -Value "$(Get-Date -Format s) $Text" -Encoding UTF8 }
function Root { wsl.exe -d $Distro -u root @args 2>&1 | ForEach-Object { "$_" } }
function Probe { (Root python3 -B $Probe @args) -join ' ' }
function Trigger([string] $Name) {
  $Task = "SIEMOUT$Name$([guid]::NewGuid().ToString('N').Substring(0, 6))"
  & schtasks.exe /create /tn $Task /tr 'cmd.exe /c exit' /sc once /st 23:59 /f 2>$null | Out-Null
  Start-Sleep -Seconds 1
  & schtasks.exe /delete /tn $Task /f 2>$null | Out-Null
  $Task
}
function WaitFor([string] $What, [string[]] $Query, [int] $Seconds) {
  $Clock = [Diagnostics.Stopwatch]::StartNew()
  while ($Clock.Elapsed.TotalSeconds -lt $Seconds) {
    if ((Probe @Query) -match 'yes') { Note "PASS $What, after $([int] $Clock.Elapsed.TotalSeconds) s"; return $true }
    Start-Sleep -Seconds 10
  }
  Note "FAIL $What, not within $Seconds s: $(Probe state)"
  $false
}

Note "=== start: $(Probe state)"

Note '=== Kafka down while an alert is due'
$Task = Trigger 'K'
WaitFor 'the event is searchable' @('event', $Task) 90 | Out-Null
Root systemctl stop kafka | Out-Null
Note "kafka: $(Root systemctl is-active kafka)"
WaitFor 'the alert waits in the outbox' @('evidence-waiting', $Task) 420 | Out-Null
Note "during: $(Probe state)"
Note "not in Kafka yet, because Kafka is down. Detector: $(Root systemctl is-active siem-detector)"
Root systemctl start kafka | Out-Null
WaitFor 'the alert reaches Kafka after recovery' @('in-kafka', $Task) 180 | Out-Null
Note "after: $(Probe state)"

Note '=== OpenSearch down, with an event made during the outage'
Root systemctl stop opensearch | Out-Null
Note "opensearch: $(Root systemctl is-active opensearch)"
$Task = Trigger 'O'
WaitFor 'the failure is recorded, with no crash' @('rule-failures') 240 | Out-Null
Note "detector during: $(Root systemctl is-active siem-detector)"
Root systemctl start opensearch | Out-Null
Note "opensearch: $(Root systemctl is-active opensearch)"
WaitFor 'the event from the outage is detected' @('in-kafka', $Task) 900 | Out-Null
Note "after: $(Probe state)"

Note '=== detector killed'
$Task = Trigger 'D'
Root systemctl kill -s KILL siem-detector | Out-Null
Start-Sleep -Seconds 40
Note "detector after 40 s: $(Root systemctl is-active siem-detector), restarts $(Root systemctl show siem-detector -p NRestarts --value)"
WaitFor 'an event from around the kill is detected' @('in-kafka', $Task) 420 | Out-Null

Note '=== clean stop and start'
$Clock = [Diagnostics.Stopwatch]::StartNew()
Root systemctl stop siem-detector | Out-Null
Note "stopped in $([math]::Round($Clock.Elapsed.TotalSeconds, 1)) s: $(Root systemctl is-active siem-detector)"
Root systemctl start siem-detector | Out-Null
Note "started: $(Root systemctl is-active siem-detector)"

Note "=== duplicates: $(Probe duplicates)"
Note "=== end: $(Probe state)"
Note 'DONE'
