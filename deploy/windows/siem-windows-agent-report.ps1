# Writes what WSL cannot see: the Windows agent's service state and delivery counters. Called by the alert watcher.
# Metrics stay on Windows loopback, and WSL has no route to them under NAT networking. Counts only, and no elevation.
# Any failure here is written into the report, or swallowed by the caller. It must never stop the alert watch.
param(
  [string] $OutFile = (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\windows-agent.json'),
  [string] $MetricsUrl = 'http://127.0.0.1:9598/metrics',
  [string] $Sink = 'kafka_raw',
  [string] $MetricsFile,
  [string] $ServiceState
)
$ErrorActionPreference = 'Stop'

function Get-AgentCounter([string[]] $Lines, [string] $Name, [string] $Component) {
  $Total = 0.0
  $Found = $false
  foreach ($Line in $Lines) {
    if ($Line.StartsWith($Name) -and $Line -match '^[a-z_]+\{(.*)\}\s+(\S+)') {
      $Labels, $Value = $Matches[1], $Matches[2]
      if ($Labels -match "component_id=`"$Component`"") {
        $Total += [double]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
        $Found = $true
      }
    }
  }
  if ($Found) { $Total } else { $null }
}

function New-AgentReport([string] $State, [string] $Text, [long] $NowMs) {
  $Metrics = @{}
  $Scrape = 'ok'
  if ($Text) {
    $Lines = $Text -split "`n"
    $Metrics = @{
      received = Get-AgentCounter $Lines 'vector_component_received_events_total' $Sink
      acknowledged = Get-AgentCounter $Lines 'vector_component_sent_events_total' $Sink
      buffered = Get-AgentCounter $Lines 'vector_buffer_size_events' $Sink
      discarded = Get-AgentCounter $Lines 'vector_component_discarded_events_total' $Sink
      errors = Get-AgentCounter $Lines 'vector_component_errors_total' $Sink
    }
  } else {
    $Scrape = 'unavailable'
  }
  @{ status = 'OK'; checked_ms = $NowMs; service = $State; metrics = $Metrics; scrape = $Scrape }
}

$Now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$State = $ServiceState
if (-not $State) {
  $Agent = Get-Service Vector -ErrorAction SilentlyContinue
  $State = if ($Agent) { "$($Agent.Status)" } else { 'NotInstalled' }
}
$Text = $null
try {
  $Text = if ($MetricsFile) { Get-Content -Raw -LiteralPath $MetricsFile } elseif ($State -eq 'Running') { (Invoke-WebRequest $MetricsUrl -UseBasicParsing -TimeoutSec 5).Content } else { $null }
} catch { $Text = $null }

$Json = New-AgentReport $State $Text $Now | ConvertTo-Json -Depth 3
$Spare = "$OutFile.tmp"
[IO.File]::WriteAllText($Spare, $Json, (New-Object Text.UTF8Encoding($false)))
Move-Item -LiteralPath $Spare -Destination $OutFile -Force
