# Live proof that the scheduled watcher, unaided, sees a real failure and its recovery. Stops Kafka for
# over two polls. The agent holds events meanwhile. Never starts the watcher itself. Results go to -Out.
param([Parameter(Mandatory)] [string] $Out)
$Distro = 'Ubuntu-24.04'
$Log = Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\alerts.log'
function Note([string] $Text) { Add-Content -LiteralPath $Out -Value "$(Get-Date -Format s) $Text" -Encoding UTF8 }
function Root { wsl.exe -d $Distro -u root @args 2>&1 | ForEach-Object { "$_" } }
function Task { Get-ScheduledTaskInfo -TaskName 'SIEM alert watch' }
$Failed = 0
function Check([string] $Name, [bool] $Ok, [string] $Detail = '') {
  Note "$(if ($Ok) { 'PASS' } else { 'FAIL' }) $Name $Detail"
  if (-not $Ok) { $script:Failed++ }
}

$Start = Task
Check 'the task has a next run time' ([bool] $Start.NextRunTime) "$($Start.NextRunTime)"
$Lines = @(Get-Content -LiteralPath $Log).Count
Root systemctl stop kafka | Out-Null
Note "kafka: $(Root systemctl is-active kafka)"
Root systemctl start siem-kafka-expiry-check.service | Out-Null
Note "report written while Kafka is down"
Start-Sleep -Seconds 370
$During = Task
Check 'the task ran by itself during the outage' ($During.LastRunTime -gt $Start.LastRunTime) "$($During.LastRunTime)"
$New = @(Get-Content -LiteralPath $Log | Select-Object -Skip $Lines)
$Raised = @($New | Where-Object { $_ -match 'source=kafka-expiry status=CHECK_FAILED' })
Check 'CHECK_FAILED reached alerts.log' ($Raised.Count -ge 1) "$($Raised.Count) lines"
$Raised | Select-Object -First 1 | ForEach-Object { Note "  $($_.Substring(0, [math]::Min(150, $_.Length)))" }
Check 'the notification was shown' (@($Raised | Where-Object { $_ -match 'shown=\[toast\]|shown=\[balloon\]' }).Count -ge 1)
Root systemctl start kafka | Out-Null
Note "kafka: $(Root systemctl is-active kafka)"
Root systemctl start siem-kafka-expiry-check.service | Out-Null
$Count = @(Get-Content -LiteralPath $Log).Count
Start-Sleep -Seconds 320
$Resolved = @(Get-Content -LiteralPath $Log | Select-Object -Skip $Count | Where-Object { $_ -match 'source=kafka-expiry status=OK' })
Check 'recovery reached alerts.log' ($Resolved.Count -ge 1) "$($Resolved.Count) lines"
$Resolved | Select-Object -First 1 | ForEach-Object { Note "  $($_.Substring(0, [math]::Min(150, $_.Length)))" }
Note "failed: $Failed"
Note 'DONE'
exit $Failed
