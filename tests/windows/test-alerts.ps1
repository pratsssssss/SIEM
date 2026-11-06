# Tests the alert decisions. Shows no notification and changes nothing.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\deploy\windows\siem-alert-lib.ps1')
$Failures = 0
$Passes = 0
function Check([string] $Name, [bool] $Ok, [string] $Detail = '') {
  if ($Ok) { $script:Passes++ } else { $script:Failures++ }
  Write-Output "$(('FAIL', 'PASS')[[int]$Ok]) $Name$(if ($Detail) { " ($Detail)" })"
}
$Now = [datetime]::UtcNow
$Fresh = [DateTimeOffset]::new($Now).ToUnixTimeMilliseconds()
function Report([string] $Status, [int64] $Stamp = $Fresh) { [pscustomobject] @{ status = $Status; message = 'm'; checked_ms = $Stamp } }
$Old = [DateTimeOffset]::new($Now.AddMinutes(-60)).ToUnixTimeMilliseconds()

foreach ($Status in 'OK', 'WARN', 'CRITICAL', 'LOST', 'CHECK_FAILED') {
  Check "$Status passes through" ((Get-AlertStatus (Report $Status) $Now 45 $true $false).Status -eq $Status)
}
Check 'missing report is CHECK_FAILED' ((Get-AlertStatus $null $Now 45 $true $false).Status -eq 'CHECK_FAILED')
Check 'report with no status is CHECK_FAILED' ((Get-AlertStatus ([pscustomobject] @{ checked_ms = $Fresh }) $Now 45 $true $false).Status -eq 'CHECK_FAILED')
Check 'report with no time is CHECK_FAILED' ((Get-AlertStatus ([pscustomobject] @{ status = 'OK' }) $Now 45 $true $false).Status -eq 'CHECK_FAILED')
Check 'stale OK is CHECK_FAILED, not OK' ((Get-AlertStatus (Report 'OK' $Old) $Now 45 $true $false).Status -eq 'CHECK_FAILED')
Check 'WSL stopped with no agent stays quiet' ((Get-AlertStatus (Report 'OK' $Old) $Now 45 $false $false).Status -eq 'STOPPED')
Check 'WSL stopped with the agent running alerts' ((Get-AlertStatus (Report 'OK' $Fresh) $Now 45 $false $true).Status -eq 'CHECK_FAILED')

function Previous([string] $Status, [double] $MinutesAgo) { [pscustomobject] @{ status = $Status; sent = $Now.AddMinutes(-$MinutesAgo).ToString('o') } }
$Alert = { param($Status) @{ Status = $Status; Message = 'm' } }
foreach ($Status in 'WARN', 'CRITICAL', 'LOST', 'CHECK_FAILED') {
  Check "$Status notifies when it first appears" ((Get-AlertAction (& $Alert $Status) (Previous 'OK' 0) $Now) -eq 'notify')
  Check "$Status notifies with no earlier state" ((Get-AlertAction (& $Alert $Status) $null $Now) -eq 'notify')
  Check "$Status does not repeat at once" ((Get-AlertAction (& $Alert $Status) (Previous $Status 5) $Now) -eq 'none')
  $Text = Get-AlertText (& $Alert $Status)
  Check "$Status has its own title" ($Text.Title -match 'SIEM' -and $Text.Title -notmatch ': LOST$') $Text.Title
}
Check 'WARN to CRITICAL notifies again' ((Get-AlertAction (& $Alert 'CRITICAL') (Previous 'WARN' 1) $Now) -eq 'notify')
Check 'CRITICAL repeats after an hour' ((Get-AlertAction (& $Alert 'CRITICAL') (Previous 'CRITICAL' 61) $Now) -eq 'notify')
Check 'WARN does not repeat after an hour' ((Get-AlertAction (& $Alert 'WARN') (Previous 'WARN' 61) $Now) -eq 'none')
Check 'WARN repeats after six hours' ((Get-AlertAction (& $Alert 'WARN') (Previous 'WARN' 361) $Now) -eq 'notify')
Check 'recovery is announced once' ((Get-AlertAction (& $Alert 'OK') (Previous 'LOST' 1) $Now) -eq 'resolved')
Check 'OK stays silent' ((Get-AlertAction (& $Alert 'OK') (Previous 'OK' 1) $Now) -eq 'none')
Check 'an unknown status still notifies' ((Get-AlertAction (& $Alert 'SOMETHING_NEW') (Previous 'SOMETHING_NEW' 1) $Now) -eq 'notify')

Write-Output "`n$Passes passed, $Failures failed"
exit ([int] ($Failures -gt 0))
