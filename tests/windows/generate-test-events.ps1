# Generates harmless, recognisable Windows events for the end-to-end test. Everything carries a
# random marker. The fake secret is random and used nowhere. Changes nothing lasting: the file and
# scheduled task it creates are removed. Writes the marker and fake secret to -Out, never to output.
param([Parameter(Mandatory)] [string] $Out)
$ErrorActionPreference = 'Continue'
$Marker = 'SIEMTEST' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$Fake = 'FAKEPW' + [guid]::NewGuid().ToString('N').Substring(0, 16)
@{ marker = $Marker; fake = $Fake; started = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $Out -Encoding ASCII

# PowerShell 4104 with a secret that redaction must remove, from a script file so the secret stays
# off the host command line and out of the classic log.
$Script = Join-Path $env:TEMP "$Marker.ps1"
"`$password = '$Fake'; `$note = '$Marker'; Get-Date | Out-Null" | Set-Content -LiteralPath $Script -Encoding ASCII
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script
Remove-Item -LiteralPath $Script -ErrorAction SilentlyContinue

# Sysmon 1, with a secret in the command line and the marker beside it.
& cmd.exe /c "echo tool.exe --password=$Fake $Marker > nul"

# Sysmon 11, 22 and 3.
$File = Join-Path $env:TEMP "$Marker.txt"
Set-Content -LiteralPath $File 'x'
Remove-Item -LiteralPath $File
Resolve-DnsName "$($Marker.ToLower()).example.com" -ErrorAction SilentlyContinue | Out-Null
try { (New-Object Net.Sockets.TcpClient).ConnectAsync('example.com', 443).Wait(3000) | Out-Null } catch { }

# Security 4625: a failed logon for an account that does not exist.
& net.exe use \\localhost\IPC$ "/user:$Marker" $Fake 2>$null | Out-Null
& net.exe use \\localhost\IPC$ /delete /y 2>$null | Out-Null

# Task Scheduler 106 and 141, and Security 4698 and 4699.
$Action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit'
Register-ScheduledTask -TaskName $Marker -Action $Action -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1)) -Force | Out-Null
Start-Sleep -Seconds 2
Unregister-ScheduledTask -TaskName $Marker -Confirm:$false
Write-Output 'generated'
