# Offline test of the Windows agent report. Uses a synthetic metrics file. It reads no real metrics and changes no service.
$ErrorActionPreference = 'Stop'
$Script = Join-Path $PSScriptRoot '..\..\deploy\windows\siem-windows-agent-report.ps1'
$Folder = Join-Path ([IO.Path]::GetTempPath()) ("siem-agent-report-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $Folder | Out-Null
$Out = Join-Path $Folder 'report.json'
$Metrics = Join-Path $Folder 'metrics.txt'
$Failed = 0
function Check([string] $Name, [bool] $Ok) {
  if ($Ok) { Write-Output "PASS $Name" } else { Write-Output "FAIL $Name"; $script:Failed++ }
}
try {
  @(
    'vector_component_received_events_total{component_id="kafka_raw",component_type="kafka"} 120 1793554526885',
    'vector_component_sent_events_total{component_id="kafka_raw",output="_default"} 100 1793554526885',
    'vector_component_sent_events_total{component_id="other",output="_default"} 999 1793554526885',
    'vector_buffer_size_events{component_id="kafka_raw"} 20 1793554526885',
    'vector_component_errors_total{component_id="kafka_raw"} 3 1793554526885'
  ) | Set-Content -LiteralPath $Metrics -Encoding Ascii

  & $Script -OutFile $Out -MetricsFile $Metrics -ServiceState 'Running'
  $Bytes = [IO.File]::ReadAllBytes($Out)
  $Report = [Text.Encoding]::UTF8.GetString($Bytes) | ConvertFrom-Json
  Check 'the file has no byte order mark, so Linux can parse it' ($Bytes[0] -ne 0xEF)
  Check 'it says the service is running' ($Report.service -eq 'Running')
  Check 'received is counted' ($Report.metrics.received -eq 120)
  Check 'only the Kafka sink counts as acknowledged' ($Report.metrics.acknowledged -eq 100)
  Check 'buffered is counted' ($Report.metrics.buffered -eq 20)
  Check 'errors are counted' ($Report.metrics.errors -eq 3)
  Check 'a counter that does not exist yet is empty, not zero' ($null -eq $Report.metrics.discarded)
  Check 'it carries a current time' ([Math]::Abs([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - [int64] $Report.checked_ms) -lt 60000)

  & $Script -OutFile $Out -ServiceState 'Stopped'
  $Report = [IO.File]::ReadAllText($Out) | ConvertFrom-Json
  Check 'a stopped service is reported' ($Report.service -eq 'Stopped')
  Check 'with no metrics, it says so' ($Report.scrape -eq 'unavailable')

  & $Script -OutFile $Out -ServiceState 'Running' -MetricsUrl 'http://127.0.0.1:1/metrics'
  $Report = [IO.File]::ReadAllText($Out) | ConvertFrom-Json
  Check 'an unreachable metrics port is not fatal' ($Report.service -eq 'Running' -and $Report.scrape -eq 'unavailable')
  Check 'no temporary file is left' (-not (Test-Path "$Out.tmp"))
  Check 'it asks for no elevation' (-not ((Get-Content -Raw $Script) -match 'RunAs|#Requires -RunAsAdministrator'))
} finally {
  Remove-Item -LiteralPath $Folder -Recurse -Force
}
Write-Output "$Failed failed"
exit $Failed
