# Read-only inventory of settings that need elevation. Changes nothing on the host.
# Run in an elevated PowerShell. Writes counts and settings only, never event content.
param(
  [string] $OutFile = (Join-Path $env:USERPROFILE "SIEM-Lab\phase7-inventory-$(Get-Date -Format yyyyMMdd-HHmmss).txt")
)
$ErrorActionPreference = 'Continue'

$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this in an elevated PowerShell.'
}

$Lines = [System.Collections.Generic.List[string]]::new()
$Lines.Add("Collected $(Get-Date -Format s)")

$Lines.Add('=== Advanced audit policy')
auditpol /get /category:* | ForEach-Object { $Lines.Add($_) }

$Lines.Add('=== Security log')
$Log = Get-WinEvent -ListLog Security
$Lines.Add("enabled=$($Log.IsEnabled) records=$($Log.RecordCount) maxMB=$([math]::Round($Log.MaximumSizeInBytes / 1MB, 1)) mode=$($Log.LogMode)")
$Oldest = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest
$Newest = Get-WinEvent -LogName Security -MaxEvents 1
$Lines.Add("oldest=$($Oldest.TimeCreated.ToString('s')) newest=$($Newest.TimeCreated.ToString('s'))")

$Lines.Add('=== Security event IDs, last 24 hours')
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = (Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue |
  Group-Object Id | Sort-Object Count -Descending |
  ForEach-Object { $Lines.Add("$($_.Name) x $($_.Count)") }

$Lines.Add('=== Sysmon optional feature')
$Feature = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction SilentlyContinue
$Lines.Add("state=$($Feature.State)")

$Lines.Add('=== PowerShell 2.0 engine')
$Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
$Lines.Add("state=$($Feature.State)")

New-Item -ItemType Directory -Force (Split-Path $OutFile) | Out-Null
$Lines | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Output "Wrote $OutFile. It contains settings and counts only."
