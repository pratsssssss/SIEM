# Lists the record IDs from the last 7 days, the agent's read window, for the event IDs it collects, so that
# run_e2e.py reconcile can compare them with OpenSearch. IDs only, never event content. Skips the
# newest minute, which may still be in flight. Needs no elevation. Restricted logs are reported and
# skipped: their delivery is proved by Sysmon continuity and the marked test events.
param([Parameter(Mandatory)] [string] $Out)
$Scope = [ordered] @{
  'Microsoft-Windows-TaskScheduler/Operational' = 106, 140, 141
  'Microsoft-Windows-Windows Defender/Operational' = 1006, 1007, 1008, 1009, 1015, 1116, 1117, 1118, 1119, 2001, 2003, 3002, 5001, 5004, 5007, 5008, 5010, 5012, 5013
  'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' = 2002, 2003, 2004, 2005, 2006, 2052, 2071, 2082, 2083, 2097, 2099
  'System' = 12, 13, 41, 104, 1074, 6005, 6006, 7034, 7040, 7045
}
$Result = [ordered] @{}
foreach ($Channel in $Scope.Keys) {
  try {
    $Result[$Channel] = @(Get-WinEvent -FilterHashtable @{ LogName = $Channel; Id = $Scope[$Channel]; StartTime = (Get-Date).AddDays(-7); EndTime = (Get-Date).AddMinutes(-1) } -ErrorAction Stop |
      ForEach-Object { $_.RecordId })
  } catch {
    Write-Output "skipped ${Channel}: $($_.Exception.Message)"
  }
}
$Result | ConvertTo-Json -Depth 3 -Compress | Set-Content -LiteralPath $Out -Encoding ASCII
