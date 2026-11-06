# Applies the approved Phase 7 Windows logging configuration, then proves it with real events.
# Run in an elevated PowerShell. Safe to run again. Stops at the first failed check.
# Does not install Sysmon, and does not enable 4688 command lines, transcription or module logging.
# Writes a backup and result.txt to a new timestamped folder. See docs/operations/windows-telemetry-preparation.md.
param(
  [string] $OutRoot = (Join-Path $env:USERPROFILE 'SIEM-Lab\phase7-config')
)
$ErrorActionPreference = 'Stop'

$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this in an elevated PowerShell.'
}

$Run = Join-Path $OutRoot (Get-Date -Format 'yyyyMMdd-HHmmss')
$Backup = Join-Path $Run 'backup'
New-Item -ItemType Directory -Force $Backup | Out-Null
$ResultFile = Join-Path $Run 'result.txt'

$PsLog = 'Microsoft-Windows-PowerShell/Operational'
$TaskLog = 'Microsoft-Windows-TaskScheduler/Operational'
$SblKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$PsPolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$AuditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$LsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$TestTask = 'SIEM-Phase7-LogTest'

# Microsoft's client recommendations for Logon/Logoff, plus the subcategories the owner listed.
$Audit = [ordered]@{
  'Process Creation'          = 'Success'
  'Process Termination'       = 'Success'
  'Credential Validation'     = 'Success and Failure'
  'Group Membership'          = 'Success'
  'Security System Extension' = 'Success and Failure'
  'Logon'                     = 'Success and Failure'
  'Logoff'                    = 'Success'
  'Special Logon'             = 'Success and Failure'
  'Account Lockout'           = 'Success'
}
$Logs = [ordered]@{
  'Security' = 134217728
  $PsLog     = 67108864
  $TaskLog   = 33554432
}

function Log([string] $Message) {
  Write-Output $Message
  Add-Content -LiteralPath $ResultFile -Value $Message -Encoding UTF8
}
function Check([string] $Name, [bool] $Ok, [string] $Detail = '') {
  Log (('PASS ' , 'FAIL ')[[int](-not $Ok)] + $Name + $(if ($Detail) { " ($Detail)" }))
  if (-not $Ok) { throw "Check failed: $Name" }
}
function Get-AuditPolicy {
  $Table = @{}
  auditpol /get /category:* /r | Where-Object { $_ } | ConvertFrom-Csv |
    ForEach-Object { $Table[$_.Subcategory] = $_.'Inclusion Setting' }
  if ($LASTEXITCODE -ne 0) { throw "auditpol /get failed: exit $LASTEXITCODE" }
  $Table
}
function Get-ChannelAccess([string] $Name) {
  ((wevtutil gl $Name | Select-String '^channelAccess: (.+)$').Matches[0].Groups[1].Value).Trim()
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
# Settings this script must never change. Compared before and after.
function Get-Untouched {
  $Lines = [System.Collections.Generic.List[string]]::new()
  $Mp = Get-MpComputerStatus
  $Lines.Add("defender rtp=$($Mp.RealTimeProtectionEnabled) tamper=$($Mp.IsTamperProtected) behaviour=$($Mp.BehaviorMonitorEnabled)")
  Get-NetFirewallProfile | Sort-Object Name | ForEach-Object {
    $Lines.Add("firewall $($_.Name) enabled=$($_.Enabled) allowed=$($_.LogAllowed) blocked=$($_.LogBlocked)")
  }
  $Hyper = (bcdedit /enum '{current}' | Select-String 'hypervisorlaunchtype')
  $Lines.Add("hypervisor=$(if ($Hyper) { ($Hyper.Line -split '\s+')[-1] } else { 'default' })")
  $Volume = if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue }
  $Lines.Add("bitlocker=$(if ($Volume) { $Volume.ProtectionStatus } else { 'unavailable' })")
  $Wsl = Join-Path $env:USERPROFILE '.wslconfig'
  $Lines.Add("wslconfig=$(if (Test-Path $Wsl) { (Get-FileHash $Wsl -Algorithm SHA256).Hash } else { 'absent' })")
  $Lines.Add("cmdline=$((Get-ItemProperty $AuditKey -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled)")
  $Lines.Add("legacyaudit=$((Get-ItemProperty $LsaKey).SCENoApplyLegacyAuditPolicy)")
  $Lines
}

$Stage = 'B backup'
try {
  Log "Started $(Get-Date -Format s), folder $Run"

  # B. Backup. Nothing changes until every file here exists.
  $AuditCsv = Join-Path $Backup 'auditpol.csv'
  auditpol /backup /file:"$AuditCsv" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed: exit $LASTEXITCODE" }
  auditpol /get /category:* | Set-Content (Join-Path $Backup 'auditpol.txt') -Encoding UTF8
  foreach ($Name in $Logs.Keys) {
    $File = ($Name -replace '[\\/]', '-') + '.txt'
    wevtutil gl $Name | Set-Content (Join-Path $Backup $File) -Encoding UTF8
  }
  $PolicyState = foreach ($Key in $PsPolicyRoot, $SblKey, "$PsPolicyRoot\ModuleLogging", "$PsPolicyRoot\Transcription") {
    "$Key exists=$(Test-Path $Key)"
    if (Test-Path $Key) { Get-ItemProperty $Key | Format-List | Out-String }
  }
  $PolicyState | Set-Content (Join-Path $Backup 'powershell-policy.txt') -Encoding UTF8
  $Untouched = @(Get-Untouched)
  $Untouched | Set-Content (Join-Path $Backup 'untouched-settings.txt') -Encoding UTF8
  $AuditBefore = Get-AuditPolicy
  Check 'audit backup has every subcategory' ((Get-Content $AuditCsv).Count -gt 50) "$((Get-Content $AuditCsv).Count) lines"
  Check 'backup files written' ((Get-ChildItem $Backup -File | Where-Object Length -gt 0).Count -ge 7)

  # C. Audit policy.
  $Stage = 'C audit policy'
  foreach ($Name in $Audit.Keys) {
    $Success = if ($Audit[$Name] -match 'Success') { 'enable' } else { 'disable' }
    $Failure = if ($Audit[$Name] -match 'Failure') { 'enable' } else { 'disable' }
    auditpol /set /subcategory:"$Name" /success:$Success /failure:$Failure | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed for ${Name}: exit $LASTEXITCODE" }
  }
  $AuditAfter = Get-AuditPolicy
  foreach ($Name in $Audit.Keys) {
    Check "audit $Name" ($AuditAfter[$Name] -eq $Audit[$Name]) $AuditAfter[$Name]
  }
  $Drift = @($AuditBefore.Keys | Where-Object { $Audit.Keys -notcontains $_ -and $AuditBefore[$_] -ne $AuditAfter[$_] })
  Check 'no other audit subcategory changed' ($Drift.Count -eq 0) ($Drift -join ', ')
  Check 'audit subcategory count unchanged' ($AuditBefore.Count -eq $AuditAfter.Count) "$($AuditAfter.Count)"

  # D. Script block logging. Invocation logging stays off, because it adds 4105 and 4106 for every block.
  $Stage = 'D script block logging'
  if (-not (Test-Path $SblKey)) { New-Item -Path $SblKey -Force | Out-Null }
  New-ItemProperty -Path $SblKey -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $SblKey -Name EnableScriptBlockInvocationLogging -Value 0 -PropertyType DWord -Force | Out-Null
  $Sbl = Get-ItemProperty $SblKey
  Check 'script block logging on' ($Sbl.EnableScriptBlockLogging -eq 1)
  Check 'invocation logging off' ($Sbl.EnableScriptBlockInvocationLogging -eq 0)

  # E. Event logs. Only read rights are removed from non-admin groups, because they keep write
  # rights so that non-admin PowerShell can still log. Stage F proves that.
  $Stage = 'E event logs'
  foreach ($Name in $Logs.Keys) {
    wevtutil sl $Name /ms:$($Logs[$Name]) /rt:false
    if ($LASTEXITCODE -ne 0) { throw "wevtutil failed for ${Name}: exit $LASTEXITCODE" }
  }
  wevtutil sl $TaskLog /e:true
  if ($LASTEXITCODE -ne 0) { throw "wevtutil could not enable the Task Scheduler log: exit $LASTEXITCODE" }
  $AccessBefore = Get-ChannelAccess $PsLog
  $AccessWanted = $AccessBefore -replace '\(A;;0x3;;;(IU|SU|S-1-5-3|S-1-5-33)\)', '(A;;0x2;;;$1)'
  if ($AccessWanted -ne $AccessBefore) {
    wevtutil sl $PsLog /ca:$AccessWanted
    if ($LASTEXITCODE -ne 0) { throw "wevtutil could not set channel access: exit $LASTEXITCODE" }
  }
  foreach ($Name in $Logs.Keys) {
    $Info = Get-WinEvent -ListLog $Name
    Check "log $Name" ($Info.IsEnabled -and $Info.MaximumSizeInBytes -eq $Logs[$Name] -and $Info.LogMode -eq 'Circular') "$($Info.MaximumSizeInBytes) bytes, $($Info.LogMode)"
  }
  Check 'PowerShell log access restricted' ((Get-ChannelAccess $PsLog) -eq $AccessWanted -and $AccessWanted -notmatch '\(A;;0x3;;;')

  # F. Prove it with real events.
  $Stage = 'F verification'
  $Start = (Get-Date).AddSeconds(-2)
  $Marker = 'SIEMPHASE7' + [guid]::NewGuid().ToString('N')

  # A real process, so the test cannot be satisfied by boot-time 4688 events.
  $Child = Start-Process cmd.exe -ArgumentList '/c exit 0' -WindowStyle Hidden -Wait -PassThru
  $Created = @(Find-Events @{ LogName = 'Security'; Id = 4688; StartTime = $Start } {
    $D = Get-Data $_; $D.NewProcessName -like '*\cmd.exe' -and [Convert]::ToInt64($D.NewProcessId, 16) -eq $Child.Id
  })
  Check '4688 for the test process' ($Created.Count -ge 1) "$($Created.Count) event"
  Check '4688 command line is empty' (-not (Get-Data $Created[0]).CommandLine)
  $Ended = @(Find-Events @{ LogName = 'Security'; Id = 4689; StartTime = $Start } {
    $D = Get-Data $_; $D.ProcessName -like '*\cmd.exe' -and [Convert]::ToInt64($D.ProcessId, 16) -eq $Child.Id
  })
  Check '4689 for the test process' ($Ended.Count -ge 1) "$($Ended.Count) event"

  # A failed check for an account that does not exist. The password is random and never stored.
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement
  $TestUser = 'siemtest' + $Marker.Substring(10, 8)
  $Context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine')
  $Valid = $Context.ValidateCredentials($TestUser, [guid]::NewGuid().ToString())
  $Context.Dispose()
  Check 'test account was rejected' (-not $Valid)
  $Validation = @(Find-Events @{ LogName = 'Security'; Id = 4776; StartTime = $Start } { (Get-Data $_).TargetUserName -eq $TestUser })
  Check '4776 credential validation failure' ($Validation.Count -ge 1) "$($Validation.Count) event"

  # A real medium-integrity process, started by a task, proves non-admin behaviour and Task Scheduler logging.
  $TestScript = Join-Path $Run 'limited-test.ps1'
  $TestResult = Join-Path $Run 'limited-test.txt'
  @"
`$Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
`$Read = 'read-allowed'
try { Get-WinEvent -LogName '$PsLog' -MaxEvents 1 -ErrorAction Stop | Out-Null } catch { `$Read = `$_.Exception.GetType().FullName }
"$Marker elevated=`$Elevated read=`$Read" | Set-Content -LiteralPath '$TestResult' -Encoding UTF8
"@ | Set-Content -LiteralPath $TestScript -Encoding UTF8

  $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$TestScript`""
  $TaskUser = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
  $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $TestTask -Action $Action -Principal $TaskUser -Settings $Settings -Force | Out-Null
  try {
    Start-ScheduledTask -TaskName $TestTask
    $End = (Get-Date).AddSeconds(60)
    while (-not (Test-Path $TestResult) -and (Get-Date) -lt $End) { Start-Sleep -Seconds 1 }
  } finally {
    Unregister-ScheduledTask -TaskName $TestTask -Confirm:$false
  }
  Check 'limited test ran' (Test-Path $TestResult)
  $Limited = (Get-Content -LiteralPath $TestResult -Raw).Trim()
  Check 'limited test was not elevated' ($Limited -match 'elevated=False')
  Check 'non-admin read of PowerShell log denied' ($Limited -match 'Unauthorized') ($Limited -replace '^\S+ ', '')

  $Blocks = @(Find-Events @{ LogName = $PsLog; Id = 4104; StartTime = $Start } { $_.Message -match $Marker })
  Check '4104 from a non-admin process' ($Blocks.Count -ge 1) "$($Blocks.Count) event"
  Check '4104 is routine logging, not the suspicious-script path' ($Blocks[0].Level -eq 5) "level $($Blocks[0].Level)"

  foreach ($Id in 106, 200, 201, 141) {
    $Events = @(Find-Events @{ LogName = $TaskLog; Id = $Id; StartTime = $Start } { $_.Message -match $TestTask })
    Check "Task Scheduler $Id" ($Events.Count -ge 1) "$($Events.Count) event"
  }

  # Group membership depends on a logon happening, so a miss here is reported, not failed.
  $Groups = @(Find-Events @{ LogName = 'Security'; Id = 4627; StartTime = $Start } { $true } 300)
  Log "$(if ($Groups.Count) { 'PASS' } else { 'NOT OBSERVED' }) 4627 group membership ($($Groups.Count) event)"

  $Lines = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $Start } -ErrorAction SilentlyContinue |
    Where-Object { (Get-Data $_).CommandLine })
  Check 'no 4688 since the change has a command line' ($Lines.Count -eq 0)
  Check 'module logging not configured' (-not (Test-Path "$PsPolicyRoot\ModuleLogging"))
  Check 'transcription not configured' (-not (Test-Path "$PsPolicyRoot\Transcription"))
  $Now = @(Get-Untouched)
  $Changed = @(Compare-Object $Untouched $Now | ForEach-Object InputObject)
  Check 'Defender, firewall, hypervisor, BitLocker, WSL and audit keys unchanged' ($Changed.Count -eq 0) ($Changed -join '; ')

  Log "RESULT PASS $(Get-Date -Format s)"
  exit 0
} catch {
  Log "RESULT FAIL at stage $Stage`: $($_.Exception.Message)"
  Log "Backup kept in $Backup"
  exit 1
}
