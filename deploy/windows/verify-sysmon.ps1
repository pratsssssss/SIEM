# Proves that Sysmon is installed and producing telemetry. Run in an elevated PowerShell.
# Creates and removes one harmless .ps1 file, and makes one HTTPS request to example.com.
# Writes settings and pass or fail lines only, never event content.
param(
  [string] $ResultFile = (Join-Path $env:USERPROFILE 'SIEM-Lab\phase7-config\sysmon-verify.txt'),
  # Sysmon64.exe's creation time is the install time, so this stays right on later runs.
  [datetime] $InstalledAfter = (Get-Item (Join-Path $env:windir 'Sysmon64.exe')).CreationTime.AddMinutes(-1)
)
$ErrorActionPreference = 'Stop'

$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this in an elevated PowerShell.'
}

$Channel = 'Microsoft-Windows-Sysmon/Operational'
$ExeSha256 = '83d31f2478dc6716cfdbf69e5c384bf043072b5f0d8d7b2eea365f709fda4352'
New-Item -ItemType Directory -Force (Split-Path $ResultFile) | Out-Null

function Log([string] $Message) {
  Write-Output $Message
  Add-Content -LiteralPath $ResultFile -Value $Message -Encoding UTF8
}
function Check([string] $Name, [bool] $Ok, [string] $Detail = '') {
  Log (('PASS ', 'FAIL ')[[int](-not $Ok)] + $Name + $(if ($Detail) { " ($Detail)" }))
  if (-not $Ok) { throw "Check failed: $Name" }
}
function Get-Data($Event) {
  $Table = @{}
  foreach ($Item in ([xml] $Event.ToXml()).Event.EventData.Data) { $Table[$Item.Name] = [string] $Item.'#text' }
  $Table
}
function Find-Events([hashtable] $Filter, [scriptblock] $Match, [int] $Seconds = 60) {
  $End = (Get-Date).AddSeconds($Seconds)
  do {
    $Found = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue | Where-Object -FilterScript $Match)
    if ($Found.Count -gt 0) { return $Found }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $End)
  @()
}

try {
  Log "Started $(Get-Date -Format s)"

  $Service = Get-Service Sysmon64
  Check 'service running' ($Service.Status -eq 'Running') "$($Service.Status), $($Service.StartType)"
  Check 'service starts automatically' ($Service.StartType -eq 'Automatic')
  # Win32_SystemDriver does not list SysmonDrv on this host, so use the service manager and filter manager.
  $Driver = Get-Service SysmonDrv
  Check 'driver running' ($Driver.Status -eq 'Running') "$($Driver.Status), $($Driver.StartType)"
  $Filters = fltmc filters
  if ($LASTEXITCODE -ne 0) { throw "fltmc failed: exit $LASTEXITCODE" }
  Check 'driver loaded as a filter' (@($Filters | Select-String '^SysmonDrv\s').Count -eq 1)
  $Installed = Join-Path $env:windir 'Sysmon64.exe'
  Check 'installed binary is the pinned one' ((Get-FileHash $Installed -Algorithm SHA256).Hash.ToLower() -eq $ExeSha256)
  $Signature = Get-AuthenticodeSignature $Installed
  Check 'installed binary signature valid' ($Signature.Status -eq 'Valid') $Signature.Status

  $Info = Get-WinEvent -ListLog $Channel
  Check 'channel enabled at 128 MiB, circular' ($Info.IsEnabled -and $Info.MaximumSizeInBytes -eq 134217728 -and $Info.LogMode -eq 'Circular') "$($Info.MaximumSizeInBytes) bytes, $($Info.LogMode)"
  $Access = ((wevtutil gl $Channel | Select-String '^channelAccess: (.+)$').Matches[0].Groups[1].Value).Trim()
  Log "INFO channel access $Access"

  $Start = (Get-Date).AddSeconds(-2)
  $Config = @(Get-WinEvent -FilterHashtable @{ LogName = $Channel; Id = 16; StartTime = $InstalledAfter } -ErrorAction SilentlyContinue)
  Check 'event 16, configuration applied' ($Config.Count -ge 1) "$($Config.Count) event"

  $Child = Start-Process cmd.exe -ArgumentList '/c exit 0' -WindowStyle Hidden -Wait -PassThru
  $Process = @(Find-Events @{ LogName = $Channel; Id = 1; StartTime = $Start } {
    $D = Get-Data $_; $D.Image -like '*\cmd.exe' -and [int] $D.ProcessId -eq $Child.Id
  })
  Check 'event 1 for the test process' ($Process.Count -ge 1) "$($Process.Count) event"
  $Hashes = (Get-Data $Process[0]).Hashes
  Check 'event 1 has SHA256 and IMPHASH' ($Hashes -match 'SHA256=' -and $Hashes -match 'IMPHASH=')

  $Name = 'siem-sysmon-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1'
  $Script = Join-Path $env:USERPROFILE "Downloads\$Name"
  Set-Content -LiteralPath $Script -Value '# harmless test file' -Encoding UTF8
  Remove-Item -LiteralPath $Script
  $File = @(Find-Events @{ LogName = $Channel; Id = 11; StartTime = $Start } { (Get-Data $_).TargetFilename -like "*$Name" })
  Check 'event 11 for the test file' ($File.Count -ge 1) "$($File.Count) event"

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest 'https://example.com' -UseBasicParsing -TimeoutSec 20 | Out-Null
  $Dns = @(Find-Events @{ LogName = $Channel; Id = 22; StartTime = $Start } { (Get-Data $_).QueryName -eq 'example.com' } 120)
  Check 'event 22 for the test request' ($Dns.Count -ge 1) "$($Dns.Count) event"
  $Net = @(Find-Events @{ LogName = $Channel; Id = 3; StartTime = $Start } {
    $D = Get-Data $_; $D.Image -like '*\powershell.exe' -and $D.DestinationPort -eq '443'
  } 120)
  Check 'event 3 for the test request' ($Net.Count -ge 1) "$($Net.Count) event"

  $Errors = @(Get-WinEvent -FilterHashtable @{ LogName = $Channel; Id = 255; StartTime = $InstalledAfter } -ErrorAction SilentlyContinue)
  Check 'no event 255' ($Errors.Count -eq 0) "$($Errors.Count) event"

  $Installs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4697; StartTime = $InstalledAfter } -ErrorAction SilentlyContinue |
    Where-Object { (Get-Data $_).ServiceName -match '^Sysmon' })
  Check '4697 for the Sysmon service' ($Installs.Count -ge 1) "$($Installs.Count) event"
  $Services = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $InstalledAfter } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Sysmon' })
  Check '7045 for the Sysmon service' ($Services.Count -ge 1) "$($Services.Count) event"
  $Groups = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4627; StartTime = $InstalledAfter } -ErrorAction SilentlyContinue)
  $Logons = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $InstalledAfter } -ErrorAction SilentlyContinue)
  Log "INFO 4627 x $($Groups.Count), 4624 x $($Logons.Count) since install"

  Log 'INFO event counts since install'
  Get-WinEvent -FilterHashtable @{ LogName = $Channel; StartTime = $InstalledAfter } -ErrorAction SilentlyContinue |
    Group-Object Id | Sort-Object Count -Descending | ForEach-Object { Log "  id $($_.Name) x $($_.Count)" }

  Log "RESULT PASS $(Get-Date -Format s)"
  exit 0
} catch {
  Log "RESULT FAIL: $($_.Exception.Message)"
  exit 1
}
