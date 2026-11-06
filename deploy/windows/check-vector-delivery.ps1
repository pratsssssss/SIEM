# Reports what the agent has really delivered. Only the Kafka sink's sent count is delivery: it
# moves when Kafka acknowledges. A source count or a checkpoint means collected, or buffered.
# Exit status: 0 acknowledged, 1 pending or no events, 2 not delivering, 3 lost, 4 check failed.
param(
  [string] $MetricsUrl = 'http://127.0.0.1:9598/metrics',
  [string] $MetricsFile,
  [string] $Sink = 'kafka_raw',
  [string] $StateFile = (Join-Path $env:USERPROFILE 'SIEM-Lab\phase8\agent-delivery.json'),
  [switch] $NoState
)
$ErrorActionPreference = 'Stop'

function Get-Metric([string[]] $Lines, [string] $Name, [string] $Component) {
  $Total = 0.0
  $Found = $false
  foreach ($Line in $Lines) {
    if ($Line -match "^$Name\{(.*)\}\s+(\S+)") {
      $Labels, $Value = $Matches[1], $Matches[2]
      if ($Labels -match "component_id=`"$Component`"") {
        $Total += [double]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
        $Found = $true
      }
    }
  }
  if ($Found) { $Total } else { $null }
}

try {
  if ($MetricsFile) {
    $Text = Get-Content -Raw -LiteralPath $MetricsFile
  } else {
    $Text = (Invoke-WebRequest $MetricsUrl -UseBasicParsing -TimeoutSec 5).Content
  }
  $Lines = $Text -split "`n"
  $Received = Get-Metric $Lines 'vector_component_received_events_total' $Sink
  $Acknowledged = Get-Metric $Lines 'vector_component_sent_events_total' $Sink
  $Buffered = Get-Metric $Lines 'vector_buffer_size_events' $Sink
  $Discarded = Get-Metric $Lines 'vector_component_discarded_events_total' $Sink
  $Errors = Get-Metric $Lines 'vector_component_errors_total' $Sink
  if ($null -eq $Received) { throw "no metrics for sink $Sink" }
  if ($null -eq $Acknowledged) { $Acknowledged = 0.0 }
  if ($null -eq $Buffered) { $Buffered = 0.0 }
  if ($null -eq $Discarded) { $Discarded = 0.0 }
  if ($null -eq $Errors) { $Errors = 0.0 }
  $Pending = $Received - $Acknowledged

  # Refused events leave the buffer unacknowledged, so an empty buffer alone proves nothing.
  if ($Discarded -gt 0 -or ($Pending -gt 0 -and $Buffered -le 0 -and $Errors -gt 0)) { $Status = 'LOST'; $Code = 3 }
  elseif ($Received -le 0) { $Status = 'NO_EVENTS'; $Code = 1 }
  elseif ($Pending -le 0 -and $Buffered -le 0) { $Status = 'ACKNOWLEDGED'; $Code = 0 }
  elseif ($Acknowledged -le 0) { $Status = 'NOT_DELIVERING'; $Code = 2 }
  else { $Status = 'PENDING'; $Code = 1 }
} catch {
  $Status = 'CHECK_FAILED'; $Code = 4
  $Received = $Acknowledged = $Buffered = $Discarded = $Errors = $Pending = $null
}

$Report = [ordered]@{
  checked      = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
  status       = $Status
  received     = $Received
  acknowledged = $Acknowledged
  pending      = $Pending
  buffered     = $Buffered
  discarded    = $Discarded
  errors       = $Errors
}
if (-not $NoState) {
  New-Item -ItemType Directory -Force (Split-Path $StateFile) | Out-Null
  $Report | ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding UTF8
}
$Report | ConvertTo-Json -Compress
exit $Code
