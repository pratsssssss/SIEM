# Real, harmless Windows activity for the correlation scenarios. See tests/correlation/run_live_correlation.py.
# -Prepare writes the names and address to -Out, and needs no elevation.
# The default run needs elevation. Nothing here downloads or runs code from the network: every bitsadmin
# call names a job that does not exist, and fails. Everything created here is removed.
# The temporary password is random, goes only to the logon API, and is never on a command line.
param([Parameter(Mandatory)] [string] $Out, [switch] $Prepare)
$ErrorActionPreference = 'Continue'

if ($Prepare) {
  $Tag = 'siemcor' + [guid]::NewGuid().ToString('N').Substring(0, 8)
  $Address = ([Net.Dns]::GetHostAddresses('example.com') | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
  @{ tag = $Tag; ip = $Address; domains = @("$Tag-a.example.com", "$Tag-b.example.com"); started = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $Out -Encoding ASCII
  return
}

$Info = Get-Content -LiteralPath $Out -Raw | ConvertFrom-Json
$Tag = $Info.tag
$Log = "$Out.log"
function Note([string] $Text) { Add-Content -LiteralPath $Log -Value "$(Get-Date -Format s) $Text" -Encoding UTF8 }
Note 'started'
$Bits = "$env:SystemRoot\System32\bitsadmin.exe"

# Scenario 1: failed logons, then a success, for a temporary account nobody else uses.
Add-Type -Namespace Siem -Name Logon -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr handle);
'@
function Try-Logon([string] $Password) {
  $Token = [IntPtr]::Zero
  $Done = [Siem.Logon]::LogonUser($Tag, '.', $Password, 3, 0, [ref] $Token)
  if ($Done) { [Siem.Logon]::CloseHandle($Token) | Out-Null }
  $Done
}
$Secret = [guid]::NewGuid().ToString('N') + 'aA1!'
try {
  New-LocalUser -Name $Tag -Password (ConvertTo-SecureString $Secret -AsPlainText -Force) -AccountNeverExpires -Description 'SIEM correlation test, removed at once' | Out-Null
  # Windows logs a repeat of one wrong password once, so each attempt differs.
  foreach ($Index in 1..7) { Try-Logon ([guid]::NewGuid().ToString('N')) | Out-Null; Start-Sleep -Milliseconds 400 }
  Start-Sleep -Seconds 20
  Note "logon with the right password: $(Try-Logon $Secret)"
} finally {
  Remove-LocalUser -Name $Tag -ErrorAction SilentlyContinue
  $Secret = $null
  Note "account removed: $(-not (Get-LocalUser -Name $Tag -ErrorAction SilentlyContinue))"
}

# Scenario 4: a new service whose program is flagged. It exits at once, so the service never really runs.
$Service = "$Tag-svc"
& sc.exe create $Service binPath= "$Bits /addfile $Tag nothing nothing" start= demand | Out-Null
Start-Sleep -Seconds 180
& sc.exe start $Service 2>&1 | Out-Null
Start-Sleep -Seconds 5
& sc.exe delete $Service | Out-Null
Note "service removed: $(-not (Get-Service -Name $Service -ErrorAction SilentlyContinue))"

# Scenario 5: a scheduled task whose program is flagged, run once by the task service.
$Task = "$Tag-task"
& schtasks.exe /create /tn $Task /tr "$Bits /addfile $Tag nothing nothing" /sc once /st 23:59 /f 2>&1 | Out-Null
Start-Sleep -Seconds 180
& schtasks.exe /run /tn $Task 2>&1 | Out-Null
Start-Sleep -Seconds 10
& schtasks.exe /delete /tn $Task /f 2>&1 | Out-Null
Note "task removed: $((schtasks.exe /query /tn $Task 2>$null | Measure-Object).Count -eq 0)"

# Scenario 7: DNS lookups for two names listed in the synthetic intelligence file.
foreach ($Name in $Info.domains) { Resolve-DnsName $Name -ErrorAction SilentlyContinue | Out-Null; Start-Sleep -Seconds 2 }

# Scenario 6: two rules fire on connections to one address, listed in the synthetic file.
foreach ($Index in 1..7) {
  $Client = New-Object Net.Sockets.TcpClient
  try { $Client.ConnectAsync($Info.ip, 80).Wait(3000) | Out-Null } catch { } finally { $Client.Close() }
  Start-Sleep -Seconds 12
}
Note 'generated'
