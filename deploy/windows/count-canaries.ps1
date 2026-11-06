# Counts canary tokens in Windows event logs. Read-only, and prints counts and event IDs only.
# Run it unelevated for the open logs, or elevated for the restricted ones. It never clears a log.
param(
  [Parameter(Mandatory)] [string] $TokenFile,
  [datetime] $Since = '2026-10-31T00:00:00',
  [string[]] $Logs = @('Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational', 'Security', 'Windows PowerShell', 'Application', 'System')
)
$ErrorActionPreference = 'Stop'
$Tokens = @(Get-Content -LiteralPath $TokenFile)
Write-Output "tokens loaded: $($Tokens.Count), values not printed"
foreach ($Log in $Logs) {
  # A filtered query reports an unreadable log as "no events", which would look like zero hits.
  try {
    Get-WinEvent -ListLog $Log -ErrorAction Stop | Out-Null
    Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction Stop | Out-Null
  } catch {
    Write-Output "$Log : NOT READABLE from this session, so not counted"
    continue
  }
  $Events = @(Get-WinEvent -FilterHashtable @{ LogName = $Log; StartTime = $Since } -ErrorAction SilentlyContinue)
  $PerToken = New-Object int[] $Tokens.Count
  $Ids = @{}
  foreach ($Event in $Events) {
    $Xml = $Event.ToXml()
    $Hit = $false
    for ($Index = 0; $Index -lt $Tokens.Count; $Index++) {
      if ($Xml.Contains($Tokens[$Index])) { $PerToken[$Index]++; $Hit = $true }
    }
    if ($Hit) { $Ids[[string] $Event.Id] = 1 + [int] $Ids[[string] $Event.Id] }
  }
  $Summary = ($Ids.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)x$($_.Value)" }) -join ' '
  Write-Output "$Log : scanned=$($Events.Count) per-token=$($PerToken -join '/') ids=[$Summary]"
}
