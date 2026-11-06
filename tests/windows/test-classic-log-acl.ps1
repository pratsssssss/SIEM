# Without -Live it reads the real permissions and tests the proposed change, altering nothing.
# With -Live, run elevated after -Apply. It proves access for real. Prints counts only.
param([switch] $Live)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\deploy\windows\classic-log-lib.ps1')
$Failures = 0
$Passes = 0
function Check([string] $Name, [bool] $Ok, [string] $Detail = '') {
  if ($Ok) { $script:Passes++ } else { $script:Failures++ }
  Write-Output "$(('FAIL', 'PASS')[[int]$Ok]) $Name$(if ($Detail) { " ($Detail)" })"
}
$Log = 'Windows PowerShell'
$Read = 1
$Write = 2
$Service = 'S-1-5-6'
$Sids = @{ SYSTEM = 'S-1-5-18'; Administrators = 'S-1-5-32-544'; Interactive = 'S-1-5-4'; Service = $Service; Batch = 'S-1-5-3'; 'Local account service' = 'S-1-5-33' }

if (-not $Live) {
  $Applied = ((wevtutil gl $Log | Select-String '^channelAccess: (.+)$').Matches[0].Groups[1].Value).Trim()
  # Once applied, the live ACL is the restricted one, so the baseline is the copy saved beforehand.
  $Saved = Join-Path $env:USERPROFILE 'SIEM-Lab\phase8\classic-log-access-before.txt'
  $Current = if (Test-Path -LiteralPath $Saved) { (Get-Content -LiteralPath $Saved -Raw).Trim() } else { $Applied }
  $Wanted = Get-RestrictedAccess $Current
  if (Test-Path -LiteralPath $Saved) { Check 'the live ACL is the restricted one' ($Applied -eq $Wanted) }
  Check 'proposed ACL differs from the current one' ($Wanted -ne $Current)
  Check 'proposed ACL parses' ($null -ne (New-Object Security.AccessControl.RawSecurityDescriptor $Wanted))
  foreach ($Name in 'SYSTEM', 'Administrators') {
    Check "$Name keeps read and write" (((Get-SddlMask $Wanted $Sids[$Name]) -band 3) -eq 3)
    Check "$Name mask is unchanged" ((Get-SddlMask $Wanted $Sids[$Name]) -eq (Get-SddlMask $Current $Sids[$Name]))
  }
  foreach ($Name in 'Interactive', 'Service', 'Batch', 'Local account service') {
    Check "$Name could read before" (((Get-SddlMask $Current $Sids[$Name]) -band $Read) -ne 0)
    Check "$Name loses read" (((Get-SddlMask $Wanted $Sids[$Name]) -band $Read) -eq 0)
    Check "$Name keeps write, so logging continues" (((Get-SddlMask $Wanted $Sids[$Name]) -band $Write) -ne 0)
  }
  foreach ($Sid in 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0') {
    Check "$Sid holds no direct access" ((Get-SddlMask $Wanted $Sid) -eq 0)
  }
  $Text = $Wanted
  Check 'only the four entries changed' (($Text -replace '\(A;;0x2;;;(IU|SU|S-1-5-3|S-1-5-33)\)', '') -eq ($Current -replace '\(A;;0x3;;;(IU|SU|S-1-5-3|S-1-5-33)\)', ''))
  Check 'applying the rule twice changes nothing' ((Get-RestrictedAccess $Wanted) -eq $Wanted)
  $Readers = @()
  try { $Readers = @(Get-LocalGroupMember -SID S-1-5-32-573) } catch { }
  Check 'Event Log Readers has no members' ($Readers.Count -eq 0) "$($Readers.Count)"
  Write-Output "current: $Current"
  Write-Output "wanted:  $Wanted"
} else {
  $Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the live test elevated.' }
  $Count = { (Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction Stop | Measure-Object).Count }
  Check 'Administrators can read' ((& $Count) -eq 1)

  # An ordinary, unelevated token: the same user, through a Limited scheduled task.
  $Folder = Join-Path $env:ProgramData "siem-acl-test-$PID"
  New-Item -ItemType Directory $Folder | Out-Null
  icacls $Folder /grant '*S-1-5-11:(OI)(CI)M' /Q | Out-Null
  $Probe = Join-Path $Folder 'probe.ps1'
  $Result = Join-Path $Folder 'result.txt'
  "`$Outcome = try { Get-WinEvent -LogName '$Log' -MaxEvents 1 -ErrorAction Stop | Out-Null; 'READ' } catch { 'DENIED' }; `$Outcome | Set-Content '$Result'" | Set-Content $Probe -Encoding ASCII
  function Invoke-As($Principal, [string] $Name) {
    Remove-Item $Result -ErrorAction SilentlyContinue
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Probe`""
    Register-ScheduledTask -TaskName $Name -Action $Action -Principal $Principal -Force | Out-Null
    Start-ScheduledTask -TaskName $Name
    for ($I = 0; $I -lt 30 -and -not (Test-Path $Result); $I++) { Start-Sleep 1 }
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    Get-Content $Result -ErrorAction SilentlyContinue
  }
  $User = "$env:USERDOMAIN\$env:USERNAME"
  Check 'ordinary user token is denied' ((Invoke-As (New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited) 'SIEM ACL probe user') -eq 'DENIED')
  Check 'SYSTEM can read' ((Invoke-As (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) 'SIEM ACL probe system') -eq 'READ')

  # Logging must still work under the ordinary token.
  $Before = (Get-WinEvent -FilterHashtable @{ LogName = $Log; StartTime = (Get-Date).AddMinutes(-1) } -ErrorAction SilentlyContinue | Measure-Object).Count
  Invoke-As (New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited) 'SIEM ACL probe write' | Out-Null
  Start-Sleep 2
  $After = (Get-WinEvent -FilterHashtable @{ LogName = $Log; StartTime = (Get-Date).AddMinutes(-2) } -ErrorAction SilentlyContinue | Measure-Object).Count
  Check 'an ordinary PowerShell session still writes to the log' ($After -gt $Before) "$Before then $After"
  Remove-Item $Folder -Recurse -Force
}
Write-Output "`n$Passes passed, $Failures failed"
exit ([int] ($Failures -gt 0))
