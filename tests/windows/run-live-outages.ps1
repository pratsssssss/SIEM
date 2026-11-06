# Stage 8.9, against the running stack with the agent live. Stops one service at a time, generates
# marked events during the outage, restores it, and checks they arrive exactly once. Needs no
# elevation. Never clears a log, and prints counts only. Results go to -Out.
param(
  [Parameter(Mandatory)] [string] $Out,
  [int] $WslMinutes = 11,
  [ValidateSet('All', 'Services', 'Wsl', 'Retest', 'Kafka')] [string] $Part = 'All'
)
$Repo = Split-Path (Split-Path $PSScriptRoot)
$Distro = 'Ubuntu-24.04'
$WslRepo = '/mnt/c' + ($Repo.Substring(2) -replace '\\', '/')
$Work = Join-Path (Split-Path $Out) 'markers'
New-Item -ItemType Directory -Force $Work | Out-Null

function Note([string] $Text) { Add-Content -LiteralPath $Out -Value "$(Get-Date -Format s) $Text" -Encoding UTF8 }
function Root { wsl.exe -d $Distro -u root @args 2>&1 | ForEach-Object { "$_" } }
function E2E { Root python3 "$WslRepo/tests/vector/run_e2e.py" @args | ForEach-Object { Note "  $_" } }
function Generate([string] $Name) {
  $File = Join-Path $Work "$Name.json"
  & "$Repo\tests\windows\generate-test-events.ps1" -Out $File | Out-Null
  $File
}
function Delivery { & "$Repo\deploy\windows\check-vector-delivery.ps1" -NoState 2>&1 | ForEach-Object { Note "  delivery: $_" } }
function WslPath([string] $Path) { '/mnt/c' + ($Path.Substring(2) -replace '\\', '/') }

function Outage([string] $Name, [string] $Service, [int] $Seconds) {
  Note "=== $Name"
  Root systemctl stop $Service | Out-Null
  Note "  stopped: $(Root systemctl is-active $Service)"
  $File = Generate $Name
  Start-Sleep -Seconds $Seconds
  Delivery
  $Clock = [Diagnostics.Stopwatch]::StartNew()
  Root systemctl start $Service | Out-Null
  Note "  started: $(Root systemctl is-active $Service), $([math]::Round($Clock.Elapsed.TotalSeconds, 1)) s"
  E2E arrived (WslPath $File)
  Delivery
  E2E state
}

Note "START $Part"
E2E state
if ($Part -eq 'Kafka') {
Note '=== kafka outage, with the expiry check forced during it'
Root systemctl stop kafka | Out-Null
Note "  stopped: $(Root systemctl is-active kafka)"
$File = Generate 'kafka-final'
Root systemctl start siem-kafka-expiry-check.service | Out-Null
Note "  kafka after the forced check: $(Root systemctl is-active kafka)"
Note "  report: $(((Root cat /home/linux/siem/data/monitor/kafka-expiry.json) -join '' | ConvertFrom-Json).status)"
Start-Sleep -Seconds 150
Delivery
Note "  kafka after 150 s: $(Root systemctl is-active kafka)"
$Clock = [Diagnostics.Stopwatch]::StartNew()
Root systemctl start kafka | Out-Null
Note "  started: $(Root systemctl is-active kafka), $([math]::Round($Clock.Elapsed.TotalSeconds, 1)) s"
E2E arrived (WslPath $File)
Delivery
Root systemctl start siem-kafka-expiry-check.service | Out-Null
Note "  report after recovery: $(((Root cat /home/linux/siem/data/monitor/kafka-expiry.json) -join '' | ConvertFrom-Json).status)"
}
elseif ($Part -eq 'Retest') {
Outage 'aggregator-retest' 'vector' 60
Outage 'opensearch-retest' 'opensearch' 60
Outage 'kafka-retest' 'kafka' 120

Note '=== frozen broker: connections stay open and nothing answers, like a network interruption'
$Pid9092 = (Root systemctl show kafka -p MainPID --value | Select-Object -First 1).Trim()
Root kill -STOP $Pid9092 | Out-Null
$File = Generate 'frozen'
Start-Sleep -Seconds 90
Delivery
Root kill -CONT $Pid9092 | Out-Null
E2E arrived (WslPath $File)
Delivery
}
elseif ($Part -ne 'Wsl') {
Outage 'aggregator' 'vector' 60
Outage 'verifier' 'seal-verifier' 60
Outage 'opensearch' 'opensearch' 60
Outage 'kafka' 'kafka' 60

Note '=== disk pressure, simulated by the real guard with a private report'
Root python3 /usr/local/lib/siem/siem-disk-guard.py --simulate-free-gib 15 --publish /tmp/siem-guard-test.json | Out-Null
Note "  aggregator after the guard: $(Root systemctl is-active vector)"
Note "  latch present: $(Root test -e /home/linux/siem/data/monitor/ingest-stopped '&&' echo yes)"
$File = Generate 'disk'
Start-Sleep -Seconds 30
Root rm /home/linux/siem/data/monitor/ingest-stopped | Out-Null
Root systemctl start vector | Out-Null
E2E arrived (WslPath $File)
Root python3 /usr/local/lib/siem/siem-disk-guard.py --publish /tmp/siem-guard-test.json | Out-Null
Root rm -f /tmp/siem-guard-test.json | Out-Null
}

if ($Part -eq 'All' -or $Part -eq 'Wsl') {
Note "=== WSL terminated with live clients, $WslMinutes minutes"
wsl.exe --terminate $Distro
Note "  distribution running: $(@(wsl.exe --list --running | Where-Object { ($_ -replace '\x00', '') -match $Distro }).Count)"
$File = Generate 'wsl-early'
Start-Sleep -Seconds ($WslMinutes * 30)
Delivery
$Late = Generate 'wsl-late'
Start-Sleep -Seconds ($WslMinutes * 30)
Delivery
$Clock = [Diagnostics.Stopwatch]::StartNew()
& "$Repo\deploy\windows\siem-up.ps1" | ForEach-Object { Note "  $_" }
Note "  stack start took $([math]::Round($Clock.Elapsed.TotalSeconds, 1)) s"
E2E arrived (WslPath $File)
E2E arrived (WslPath $Late)
Delivery
}

Note '=== after all outages'
E2E state
E2E unique
E2E continuity
E2E listeners
Note 'DONE'
