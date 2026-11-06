# Registers the inventory snapshot for the current user, at logon and every six hours while logged on. Needs no
# elevation, and reads only what a normal user can read.
$ErrorActionPreference = 'Stop'
$Script = Join-Path $PSScriptRoot 'siem-asset-collect.ps1'
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Script`""
$Repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6)
$AtLogOn = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$AtLogOn.Repetition = $Repeat.Repetition
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName 'SIEM asset inventory' -Action $Action -Trigger @($AtLogOn, $Repeat) -Settings $Settings -Force | Out-Null
if (-not (Get-ScheduledTaskInfo -TaskName 'SIEM asset inventory').NextRunTime) {
  throw 'SIEM asset inventory has no next run time, so it would not repeat.'
}
