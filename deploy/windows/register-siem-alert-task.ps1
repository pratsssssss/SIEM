# Registers the alert watcher for the current user, every five minutes while logged on. Needs no
# elevation. It must run in the user's session, because a service cannot show a notification.
$ErrorActionPreference = 'Stop'
$Script = Join-Path $PSScriptRoot 'siem-alert-watch.ps1'
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Script`""
$Repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
# The logon trigger alone repeats only from the next logon, so the task would sit idle until then.
$AtLogOn = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$AtLogOn.Repetition = $Repeat.Repetition
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask -TaskName 'SIEM alert watch' -Action $Action -Trigger @($AtLogOn, $Repeat) -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName 'SIEM alert watch'
if (-not (Get-ScheduledTaskInfo -TaskName 'SIEM alert watch').NextRunTime) {
  throw 'SIEM alert watch has no next run time, so it would not repeat.'
}
