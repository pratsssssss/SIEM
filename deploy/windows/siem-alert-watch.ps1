# Shows a Windows notification for WARN, CRITICAL, LOST and CHECK_FAILED, and when they clear.
# Runs in the operator's session every five minutes, from register-siem-alert-task.ps1, because
# only that session can show a notification. Reports hold counts and ages, never event content.
# Every outcome is also written to alerts.log, so a notification that was missed can be found.
# If a notification cannot be shown, a message box appears instead.
param(
  [string[]] $ReportFile = @((Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\kafka-expiry.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\disk-guard.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\detector.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\enricher.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\correlator.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\asset.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\linux-agent.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\path.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\health.json'), (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\health-watchdog.json')),
  [string] $MemoryFile = (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\alert-state.json'),
  [string] $LogFile = (Join-Path $env:USERPROFILE 'SIEM-Lab\monitor\alerts.log'),
  [string] $Distro = 'Ubuntu-24.04',
  [int] $MaxAgeMinutes = 45,
  [string] $ForceWslRunning = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'siem-alert-lib.ps1')
$AppId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'

function Show-Notification([string] $Title, [string] $Body) {
  try {
    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId)
    if ("$($Notifier.Setting)" -ne 'Enabled') { throw "notifications are $($Notifier.Setting)" }
    $Xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $Text = { param($Value) [Security.SecurityElement]::Escape($Value) }
    $Xml.LoadXml("<toast scenario=`"reminder`"><visual><binding template=`"ToastGeneric`"><text>$(& $Text $Title)</text><text>$(& $Text $Body)</text></binding></visual><actions><action content=`"Dismiss`" arguments=`"dismiss`" activationType=`"system`"/></actions></toast>")
    $Toast = New-Object Windows.UI.Notifications.ToastNotification $Xml
    $Toast.Tag = 'siem-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $Toast.Group = 'siem-alerts'
    $Notifier.Show($Toast)
    'toast'
  } catch {
    (New-Object -ComObject WScript.Shell).Popup("$Title`n`n$Body", 300, 'SIEM alert', 48) | Out-Null
    "message box, because: $($_.Exception.Message)"
  }
}

$Folder = Split-Path $LogFile
# The health monitor reads this. A failure here must not stop the alert watch.
try { & (Join-Path $PSScriptRoot 'siem-windows-agent-report.ps1') } catch { }
New-Item -ItemType Directory -Force $Folder | Out-Null
$Now = Get-Date
$Memory = @{}
try {
  $Loaded = [IO.File]::ReadAllText($MemoryFile) | ConvertFrom-Json
  foreach ($Item in $Loaded.PSObject.Properties) { $Memory[$Item.Name] = $Item.Value }
} catch { }

$WslRunning = if ($ForceWslRunning) { $ForceWslRunning -eq 'yes' } else {
  (((wsl.exe --list --running --quiet) -join '') -replace "`0", '') -match [regex]::Escape($Distro)
}
$Agent = Get-Service Vector -ErrorAction SilentlyContinue
$AgentRunning = [bool] ($Agent -and $Agent.Status -eq 'Running')

foreach ($File in $ReportFile) {
  $Source = [IO.Path]::GetFileNameWithoutExtension($File)
  $Report = $null
  try { $Report = [IO.File]::ReadAllText($File) | ConvertFrom-Json } catch { }
  $Previous = $Memory[$Source]
  $Current = Get-AlertStatus $Report $Now $MaxAgeMinutes $WslRunning $AgentRunning
  $Action = Get-AlertAction $Current $Previous $Now
  $Stamp = $Now.ToUniversalTime().ToString('o')
  $Sent = if ($Previous -and $Previous.sent) { $Previous.sent } else { $null }
  $How = 'not shown'
  if ($Action -eq 'notify') {
    $Text = Get-AlertText $Current $Source
    $How = Show-Notification $Text.Title $Text.Body
    $Sent = $Stamp
  } elseif ($Action -eq 'resolved') {
    $How = Show-Notification "SIEM ${Source}: alert cleared" "Status is now $($Current.Status)."
    $Sent = $null
  }
  Add-Content -LiteralPath $LogFile -Value "$Stamp source=$Source status=$($Current.Status) action=$Action shown=[$How] $($Current.Message)" -Encoding UTF8
  $Memory[$Source] = @{ status = $Current.Status; sent = $Sent }
  Write-Output "$Source $($Current.Status) $Action [$How]"
}
$Memory | ConvertTo-Json | Set-Content -LiteralPath $MemoryFile -Encoding UTF8
